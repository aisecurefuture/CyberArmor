// AIShields Protect - macOS Endpoint Security System Extension
// Monitors process execution, file access, and network connections for AI security.
//
// Requires entitlements:
//   - com.apple.developer.endpoint-security.client
//   - com.apple.developer.system-extension.install
//
// Build: swiftc -framework EndpointSecurity -framework Foundation AIShieldsEndpointSecurity.swift

import Foundation
import EndpointSecurity
import os.log

let logger = Logger(subsystem: "ai.aishields.endpoint-security", category: "monitor")

// MARK: - Configuration

struct AIShieldsConfig {
    var controlPlaneURL: String
    var apiKey: String
    var tenantId: String
    var monitoredAIProcesses: Set<String>
    var sensitiveDirectories: [String]
    var aiAPIDomains: Set<String>
    var cloudSyncDirectories: [String]
    var mode: MonitorMode

    enum MonitorMode {
        case monitor   // Log only
        case enforce   // Block violations
    }

    static var `default`: AIShieldsConfig {
        AIShieldsConfig(
            controlPlaneURL: ProcessInfo.processInfo.environment["CONTROL_PLANE_URL"] ?? "",
            apiKey: ProcessInfo.processInfo.environment["API_KEY"] ?? "",
            tenantId: ProcessInfo.processInfo.environment["TENANT_ID"] ?? "",
            monitoredAIProcesses: [
                "ChatGPT", "chatgpt", "Copilot", "copilot", "Claude", "claude",
                "ollama", "Ollama", "LM Studio", "lm-studio",
                "Cursor", "cursor", "windsurf",
                "Midjourney", "Stable Diffusion", "ComfyUI",
                "text-generation-webui", "llamacpp", "llama-server",
            ],
            sensitiveDirectories: [
                "/Users/*/Documents/", "/Users/*/Desktop/",
                "/Users/*/.ssh/", "/Users/*/.aws/",
                "/Users/*/.kube/", "/Users/*/.gnupg/",
                "/private/etc/", "/var/root/",
            ],
            aiAPIDomains: [
                "api.openai.com", "api.anthropic.com",
                "generativelanguage.googleapis.com",
                "api.cohere.ai", "api-inference.huggingface.co",
                "api.mistral.ai", "api.together.xyz",
            ],
            cloudSyncDirectories: [
                "/Users/*/Library/CloudStorage/",
                "/Users/*/Dropbox/",
                "/Users/*/Google Drive/",
                "/Users/*/OneDrive/",
            ],
            mode: .monitor
        )
    }
}

// MARK: - Event Types

struct SecurityEvent: Codable {
    let timestamp: Date
    let eventType: String
    let processName: String
    let processPath: String
    let pid: Int32
    let uid: UInt32
    let severity: String
    let action: String
    let details: [String: String]
}

// MARK: - Telemetry Reporter

actor TelemetryReporter {
    private let config: AIShieldsConfig
    private var buffer: [SecurityEvent] = []
    private let maxBufferSize = 100
    private let flushInterval: TimeInterval = 10

    init(config: AIShieldsConfig) {
        self.config = config
        Task { await self.startFlushTimer() }
    }

    func report(_ event: SecurityEvent) {
        buffer.append(event)
        if buffer.count >= maxBufferSize {
            Task { await flush() }
        }
    }

    private func startFlushTimer() {
        Timer.scheduledTimer(withTimeInterval: flushInterval, repeats: true) { _ in
            Task { await self.flush() }
        }
    }

    private func flush() async {
        guard !buffer.isEmpty, !config.controlPlaneURL.isEmpty else { return }
        let events = buffer
        buffer.removeAll()

        guard let url = URL(string: "\(config.controlPlaneURL)/api/v1/telemetry/batch") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(config.apiKey, forHTTPHeaderField: "x-api-key")

        let payload: [String: Any] = [
            "tenant_id": config.tenantId,
            "source": "macos_endpoint_security",
            "events": events.map { event in
                [
                    "timestamp": ISO8601DateFormatter().string(from: event.timestamp),
                    "event_type": event.eventType,
                    "process": event.processName,
                    "pid": event.pid,
                    "severity": event.severity,
                    "action": event.action,
                    "details": event.details,
                ] as [String: Any]
            }
        ]

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: payload)
            let (_, response) = try await URLSession.shared.data(for: request)
            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode != 200 {
                logger.warning("Telemetry send failed: HTTP \(httpResponse.statusCode)")
            }
        } catch {
            logger.warning("Telemetry send error: \(error.localizedDescription)")
        }
    }
}

// MARK: - Endpoint Security Monitor

class AIShieldsESMonitor {
    private var esClient: OpaquePointer?
    private let config: AIShieldsConfig
    private let reporter: TelemetryReporter
    private var running = false

    init(config: AIShieldsConfig = .default) {
        self.config = config
        self.reporter = TelemetryReporter(config: config)
    }

    func start() -> Bool {
        var client: OpaquePointer?

        let result = es_new_client(&client) { [weak self] (client, message) in
            self?.handleMessage(message.pointee)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let esClient = client else {
            logger.error("Failed to create ES client: \(String(describing: result))")
            return false
        }

        self.esClient = esClient

        // Subscribe to events
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,        // Process execution
            ES_EVENT_TYPE_NOTIFY_OPEN,         // File open
            ES_EVENT_TYPE_AUTH_OPEN,           // File open (auth - can block)
            ES_EVENT_TYPE_NOTIFY_WRITE,        // File write
            ES_EVENT_TYPE_NOTIFY_RENAME,       // File rename
            ES_EVENT_TYPE_NOTIFY_SIGNAL,       // Process signals
            ES_EVENT_TYPE_NOTIFY_FORK,         // Process fork
        ]

        let subResult = es_subscribe(esClient, events, UInt32(events.count))
        guard subResult == ES_RETURN_SUCCESS else {
            logger.error("Failed to subscribe to ES events")
            es_delete_client(esClient)
            return false
        }

        // Clear cache to ensure we get all events
        es_clear_cache(esClient)

        running = true
        logger.info("AIShields Endpoint Security monitor started")
        return true
    }

    func stop() {
        running = false
        if let client = esClient {
            es_unsubscribe_all(client)
            es_delete_client(client)
            esClient = nil
        }
        logger.info("AIShields Endpoint Security monitor stopped")
    }

    // MARK: - Event Handlers

    private func handleMessage(_ message: es_message_t) {
        switch message.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            handleExec(message)

        case ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_AUTH_OPEN:
            handleFileOpen(message)

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            handleFileWrite(message)

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            handleFileRename(message)

        default:
            break
        }

        // For AUTH events, respond with allow (in monitor mode)
        if message.action_type == ES_ACTION_TYPE_AUTH {
            if let client = esClient {
                if config.mode == .monitor {
                    es_respond_auth_result(client, &message, ES_AUTH_RESULT_ALLOW, false)
                }
            }
        }
    }

    private func handleExec(_ message: es_message_t) {
        let process = message.process.pointee
        let execEvent = message.event.exec
        let targetPath = getString(from: execEvent.target.pointee.executable.pointee.path)
        let processName = getString(from: process.executable.pointee.path)
        let pid = audit_token_to_pid(process.audit_token)
        let uid = audit_token_to_euid(process.audit_token)

        let basename = (targetPath as NSString).lastPathComponent

        // Check if it's a monitored AI process
        if config.monitoredAIProcesses.contains(basename) {
            let event = SecurityEvent(
                timestamp: Date(),
                eventType: "ai_process_launch",
                processName: basename,
                processPath: targetPath,
                pid: pid,
                uid: uid,
                severity: "medium",
                action: "detected",
                details: [
                    "parent_process": processName,
                    "target_executable": targetPath,
                ]
            )
            Task { await reporter.report(event) }
            logger.info("AI process detected: \(basename) (PID: \(pid))")
        }
    }

    private func handleFileOpen(_ message: es_message_t) {
        let process = message.process.pointee
        let openEvent = message.event.open
        let filePath = getString(from: openEvent.file.pointee.path)
        let pid = audit_token_to_pid(process.audit_token)
        let uid = audit_token_to_euid(process.audit_token)
        let processName = (getString(from: process.executable.pointee.path) as NSString).lastPathComponent

        // Check if the process is an AI tool accessing sensitive files
        if config.monitoredAIProcesses.contains(processName) {
            for sensitiveDir in config.sensitiveDirectories {
                let pattern = sensitiveDir.replacingOccurrences(of: "*", with: "")
                if filePath.contains(pattern) || matchesGlob(filePath, pattern: sensitiveDir) {
                    let event = SecurityEvent(
                        timestamp: Date(),
                        eventType: "sensitive_file_access",
                        processName: processName,
                        processPath: getString(from: process.executable.pointee.path),
                        pid: pid,
                        uid: uid,
                        severity: "high",
                        action: config.mode == .enforce ? "blocked" : "detected",
                        details: [
                            "file_path": filePath,
                            "sensitive_directory": sensitiveDir,
                        ]
                    )
                    Task { await reporter.report(event) }
                    logger.warning("Sensitive file access by AI tool: \(processName) -> \(filePath)")

                    // Block in enforce mode
                    if config.mode == .enforce, message.action_type == ES_ACTION_TYPE_AUTH {
                        if let client = esClient {
                            es_respond_auth_result(client, &message, ES_AUTH_RESULT_DENY, false)
                            return
                        }
                    }
                    break
                }
            }
        }

        // Check for writes to cloud sync directories (DLP)
        for cloudDir in config.cloudSyncDirectories {
            let pattern = cloudDir.replacingOccurrences(of: "*", with: "")
            if filePath.contains(pattern) {
                let event = SecurityEvent(
                    timestamp: Date(),
                    eventType: "cloud_sync_access",
                    processName: processName,
                    processPath: getString(from: process.executable.pointee.path),
                    pid: pid,
                    uid: uid,
                    severity: "low",
                    action: "detected",
                    details: ["file_path": filePath, "cloud_provider": cloudDir]
                )
                Task { await reporter.report(event) }
                break
            }
        }
    }

    private func handleFileWrite(_ message: es_message_t) {
        let process = message.process.pointee
        let writeEvent = message.event.write
        let filePath = getString(from: writeEvent.target.pointee.path)
        let pid = audit_token_to_pid(process.audit_token)
        let processName = (getString(from: process.executable.pointee.path) as NSString).lastPathComponent

        // Monitor AI processes writing files
        if config.monitoredAIProcesses.contains(processName) {
            let event = SecurityEvent(
                timestamp: Date(),
                eventType: "ai_file_write",
                processName: processName,
                processPath: getString(from: process.executable.pointee.path),
                pid: pid,
                uid: audit_token_to_euid(process.audit_token),
                severity: "medium",
                action: "detected",
                details: ["file_path": filePath]
            )
            Task { await reporter.report(event) }
        }
    }

    private func handleFileRename(_ message: es_message_t) {
        let process = message.process.pointee
        let renameEvent = message.event.rename
        let sourcePath = getString(from: renameEvent.source.pointee.path)
        let pid = audit_token_to_pid(process.audit_token)

        // Detect potential data exfiltration via rename to cloud sync dirs
        if let destDir = renameEvent.destination.new_path {
            let destPath = getString(from: destDir.dir.pointee.path)
            for cloudDir in config.cloudSyncDirectories {
                let pattern = cloudDir.replacingOccurrences(of: "*", with: "")
                if destPath.contains(pattern) {
                    let event = SecurityEvent(
                        timestamp: Date(),
                        eventType: "file_move_to_cloud",
                        processName: (getString(from: process.executable.pointee.path) as NSString).lastPathComponent,
                        processPath: getString(from: process.executable.pointee.path),
                        pid: pid,
                        uid: audit_token_to_euid(process.audit_token),
                        severity: "high",
                        action: "detected",
                        details: ["source": sourcePath, "destination": destPath]
                    )
                    Task { await reporter.report(event) }
                    break
                }
            }
        }
    }

    // MARK: - Helpers

    private func getString(from esString: es_string_token_t) -> String {
        if let data = esString.data {
            return String(cString: data)
        }
        return ""
    }

    private func matchesGlob(_ path: String, pattern: String) -> Bool {
        let cleaned = pattern.replacingOccurrences(of: "*", with: "")
        return path.contains(cleaned)
    }
}

// MARK: - Main Entry Point

@main
struct AIShieldsEndpointSecurityExtension {
    static func main() {
        logger.info("AIShields Endpoint Security Extension starting...")

        let config = AIShieldsConfig.default
        let monitor = AIShieldsESMonitor(config: config)

        guard monitor.start() else {
            logger.error("Failed to start Endpoint Security monitor")
            exit(1)
        }

        // Run until terminated
        let runLoop = RunLoop.current
        let signal = DispatchSource.makeSignalSource(signal: SIGTERM)
        signal.setEventHandler {
            logger.info("Received SIGTERM, shutting down...")
            monitor.stop()
            exit(0)
        }
        signal.resume()

        // Keep running
        while true {
            runLoop.run(mode: .default, before: .distantFuture)
        }
    }
}
