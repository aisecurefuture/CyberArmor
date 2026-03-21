<?php

declare(strict_types=1);

namespace CyberArmor;

use CyberArmor\Policy\Decision;
use CyberArmor\Policy\PolicyViolationException;

/**
 * Primary client for the CyberArmor AI Identity Control Plane.
 *
 * All constructor parameters read from environment variables:
 *
 *   CYBERARMOR_URL
 *   CYBERARMOR_AGENT_ID
 *   CYBERARMOR_AGENT_SECRET
 *   CYBERARMOR_AUDIT_URL
 *   CYBERARMOR_ENFORCE_MODE  enforce (default) | monitor
 *   CYBERARMOR_FAIL_OPEN     true | false (default)
 *
 * Example:
 *   $client   = new \CyberArmor\Client();
 *   $decision = $client->checkPolicy('Hello AI', 'gpt-4o', 'openai', 'acme-corp');
 *   if (!$decision->isAllowed()) {
 *       throw new \RuntimeException('Request denied');
 *   }
 */
final class Client
{
    private const SDK_VERSION   = '2.0.0';
    private const SDK_LANG      = 'php';
    private const TIMEOUT_SEC   = 5;
    private const CONNECT_TIMEOUT_SEC = 3;

    private string  $url;
    private string  $agentId;
    private string  $agentSecret;
    private string  $enforceMode;
    private bool    $failOpen;
    private ?string $auditUrl;

    /**
     * @param string|null $url          Agent Identity Service base URL.
     * @param string|null $agentId      SDK agent identifier.
     * @param string|null $agentSecret  Shared HMAC secret for request signing.
     * @param string      $enforceMode  "enforce" or "monitor".
     * @param bool        $failOpen     Allow requests when control plane is unreachable.
     * @param string|null $auditUrl     Audit service base URL.
     *
     * @throws \InvalidArgumentException if required configuration is missing.
     */
    public function __construct(
        ?string $url         = null,
        ?string $agentId     = null,
        ?string $agentSecret = null,
        string  $enforceMode = 'enforce',
        bool    $failOpen    = false,
        ?string $auditUrl    = null,
    ) {
        $this->url         = $this->resolveUrl($url);
        $this->agentId     = $agentId
            ?? getenv('CYBERARMOR_AGENT_ID')
            ?: throw new \InvalidArgumentException('CYBERARMOR_AGENT_ID is required');
        $this->agentSecret = $agentSecret
            ?? getenv('CYBERARMOR_AGENT_SECRET')
            ?: throw new \InvalidArgumentException('CYBERARMOR_AGENT_SECRET is required');

        $envMode           = getenv('CYBERARMOR_ENFORCE_MODE') ?: 'enforce';
        $this->enforceMode = strtolower($enforceMode !== 'enforce' ? $enforceMode : $envMode);

        $envFailOpen       = strtolower(getenv('CYBERARMOR_FAIL_OPEN') ?: 'false');
        $this->failOpen    = $failOpen || ($envFailOpen === 'true');

        $this->auditUrl    = $auditUrl ?? (getenv('CYBERARMOR_AUDIT_URL') ?: null);

        if (!in_array($this->enforceMode, ['enforce', 'monitor'], true)) {
            throw new \InvalidArgumentException(
                sprintf("Invalid enforce_mode '%s'. Must be 'enforce' or 'monitor'.", $this->enforceMode)
            );
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Evaluate a policy for an AI request.
     *
     * @param string $prompt    The raw user prompt.
     * @param string $model     Model identifier, e.g. "gpt-4o".
     * @param string $provider  Provider name, e.g. "openai".
     * @param string $tenantId  Tenant identifier.
     *
     * @return Decision
     * @throws PolicyViolationException  When denied in enforce mode.
     */
    public function checkPolicy(
        string $prompt,
        string $model,
        string $provider,
        string $tenantId,
    ): Decision {
        $payload = [
            'agent_id'  => $this->agentId,
            'prompt'    => $prompt,
            'model'     => $model,
            'provider'  => $provider,
            'timestamp' => $this->nowIso8601(),
        ];

        try {
            $path     = '/policies/' . rawurlencode($tenantId) . '/evaluate';
            $response = $this->post($path, $payload);
            $decision = Decision::fromArray($response);
        } catch (\Throwable $e) {
            return $this->handleControlPlaneFailure($e, $prompt);
        }

        if (!$decision->isAllowed()) {
            if ($this->enforceMode === 'enforce') {
                throw new PolicyViolationException(
                    $decision->decisionType,
                    $decision->reason,
                );
            }
            // Monitor mode: log and allow
            $this->log('warning', sprintf(
                '[CyberArmor] Policy DENIED (monitor mode — allowing): %s',
                $decision->reason
            ));
            return new Decision(
                allowed:        true,
                decisionType:   $decision->decisionType,
                reason:         $decision->reason,
                redactedPrompt: $decision->redactedPrompt,
            );
        }

        return $decision;
    }

    /**
     * Emit an audit event to the audit service.
     *
     * Failures are non-fatal and are only logged.
     *
     * @param array<string, mixed> $event
     */
    public function emitAudit(array $event): void
    {
        if ($this->auditUrl === null) {
            return;
        }

        try {
            $this->post('/audit/events', $event, $this->auditUrl);
        } catch (\Throwable $e) {
            $this->log('error', sprintf('[CyberArmor] Audit emission failed: %s', $e->getMessage()));
        }
    }

    public function getAgentId(): string
    {
        return $this->agentId;
    }

    public function getEnforceMode(): string
    {
        return $this->enforceMode;
    }

    public function isFailOpen(): bool
    {
        return $this->failOpen;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Perform a signed JSON POST request.
     *
     * @param string                $path    URL path with leading slash.
     * @param array<string, mixed>  $body    Request body to JSON-encode.
     * @param string|null           $baseUrl Override the default control-plane URL.
     * @return array<string, mixed>          Decoded JSON response.
     *
     * @throws \RuntimeException On HTTP error or curl failure.
     */
    private function post(string $path, array $body, ?string $baseUrl = null): array
    {
        $target   = rtrim($baseUrl ?? $this->url, '/');
        $url      = $target . $path;
        $bodyJson = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        $sig      = $this->signRequest($bodyJson);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $bodyJson,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT_SEC,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT_SEC,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
                'X-CyberArmor-Agent: ' . $this->agentId,
                'X-CyberArmor-Sig: '   . $sig,
                'X-CyberArmor-SDK: php/' . self::SDK_VERSION,
            ],
        ]);

        $responseBody = curl_exec($ch);
        $httpCode     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError    = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false || $curlError !== '') {
            throw new \RuntimeException('CyberArmor HTTP request failed: ' . $curlError);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException(
                sprintf('CyberArmor HTTP %d: %s', $httpCode, $responseBody)
            );
        }

        $decoded = json_decode((string) $responseBody, true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($decoded)) {
            throw new \RuntimeException('CyberArmor: unexpected non-object JSON response');
        }

        return $decoded;
    }

    /**
     * HMAC-SHA256 signature over the JSON body using the agent secret.
     */
    private function signRequest(string $bodyJson): string
    {
        return hash_hmac('sha256', $bodyJson, $this->agentSecret);
    }

    /**
     * Handle a failure to reach the control plane according to the fail_open policy.
     */
    private function handleControlPlaneFailure(\Throwable $e, string $prompt): Decision
    {
        $this->log('error', sprintf('[CyberArmor] Control plane unreachable: %s', $e->getMessage()));

        if ($this->failOpen) {
            $this->log('warning', '[CyberArmor] fail_open=true — allowing request despite control plane failure');
            return new Decision(
                allowed:        true,
                decisionType:   'ALLOW',
                reason:         'Control plane unreachable; fail_open=true',
                redactedPrompt: null,
            );
        }

        if ($this->enforceMode === 'enforce') {
            throw new PolicyViolationException(
                'DENY',
                'Control plane unreachable and fail_open=false: ' . $e->getMessage(),
                0,
                $e,
            );
        }

        // Monitor mode fallback
        $this->log('warning', '[CyberArmor] Control plane unreachable (monitor mode — allowing)');
        return new Decision(
            allowed:        true,
            decisionType:   'DENY',
            reason:         'Control plane unreachable (monitor mode)',
            redactedPrompt: null,
        );
    }

    private function resolveUrl(?string $provided): string
    {
        $url = $provided
            ?? getenv('CYBERARMOR_URL')
            ?: null;

        if ($url === null || $url === '') {
            throw new \InvalidArgumentException('CYBERARMOR_URL is required');
        }

        return rtrim($url, '/');
    }

    private function nowIso8601(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z');
    }

    /** @param string $level  "info" | "warning" | "error" */
    private function log(string $level, string $message): void
    {
        // Simple SAPI error_log integration. Applications may replace this by
        // extending the class or injecting a PSR-3 logger in a subclass.
        error_log(strtoupper($level) . ' ' . $message);
    }
}
