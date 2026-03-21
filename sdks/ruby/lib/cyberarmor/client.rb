# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'logger'
require 'time'

module CyberArmor
  # Primary client for the CyberArmor AI Identity Control Plane.
  #
  # All parameters read from CYBERARMOR_* environment variables when not supplied:
  #
  #   CYBERARMOR_URL
  #   CYBERARMOR_AGENT_ID
  #   CYBERARMOR_AGENT_SECRET
  #   CYBERARMOR_AUDIT_URL
  #   CYBERARMOR_ENFORCE_MODE  "enforce" (default) | "monitor"
  #   CYBERARMOR_FAIL_OPEN     "true" | "false" (default)
  #
  # Example:
  #   client = CyberArmor::Client.new
  #   decision = client.check_policy(
  #     prompt:    "Summarise this document",
  #     model:     "gpt-4o",
  #     provider:  "openai",
  #     tenant_id: "acme-corp"
  #   )
  #   raise "Denied" unless decision.allowed?
  class Client
    DEFAULT_TIMEOUT    = 5   # seconds
    DEFAULT_OPEN_TIMEOUT = 3 # seconds

    attr_reader :url, :agent_id, :enforce_mode, :fail_open, :audit_url

    # @param url          [String, nil]  Agent Identity Service base URL
    # @param agent_id     [String, nil]  SDK agent identifier
    # @param agent_secret [String, nil]  Shared HMAC secret for request signing
    # @param enforce_mode [String]       "enforce" or "monitor"
    # @param fail_open    [Boolean]      Allow requests when control plane unreachable
    # @param audit_url    [String, nil]  Audit service base URL
    # @param logger       [Logger, nil]  Custom logger (defaults to STDOUT)
    # @param timeout      [Integer]      HTTP read timeout in seconds
    def initialize(
      url:          nil,
      agent_id:     nil,
      agent_secret: nil,
      enforce_mode: nil,
      fail_open:    nil,
      audit_url:    nil,
      logger:       nil,
      timeout:      DEFAULT_TIMEOUT
    )
      @url          = resolve_url(url)
      @agent_id     = agent_id     || ENV['CYBERARMOR_AGENT_ID']     || raise(ArgumentError, 'CYBERARMOR_AGENT_ID is required')
      @agent_secret = agent_secret || ENV['CYBERARMOR_AGENT_SECRET'] || raise(ArgumentError, 'CYBERARMOR_AGENT_SECRET is required')
      @enforce_mode = (enforce_mode || ENV.fetch('CYBERARMOR_ENFORCE_MODE', 'enforce')).to_s.downcase
      @fail_open    = resolve_bool(fail_open, ENV.fetch('CYBERARMOR_FAIL_OPEN', 'false'))
      @audit_url    = audit_url    || ENV['CYBERARMOR_AUDIT_URL']
      @timeout      = timeout
      @logger       = logger || Logger.new($stdout, progname: 'CyberArmor')

      validate_enforce_mode!
    end

    # Evaluate a policy for an AI request.
    #
    # @param prompt    [String] the raw user prompt
    # @param model     [String] model identifier, e.g. "gpt-4o"
    # @param provider  [String] provider name, e.g. "openai"
    # @param tenant_id [String] tenant identifier
    # @return [CyberArmor::Policy::Decision]
    # @raise [CyberArmor::Policy::PolicyViolationError] when denied in enforce mode
    def check_policy(prompt:, model:, provider:, tenant_id:)
      payload = {
        agent_id:  @agent_id,
        prompt:    prompt,
        model:     model,
        provider:  provider,
        timestamp: Time.now.utc.iso8601(3)
      }

      begin
        response = post("/policies/#{URI.encode_uri_component(tenant_id)}/evaluate", payload)
        decision = Policy::Decision.from_hash(response)
      rescue => e
        return handle_control_plane_failure(e, prompt)
      end

      unless decision.allowed?
        if enforce_mode == 'enforce'
          raise Policy::PolicyViolationError.new(
            decision_type: decision.decision_type,
            reason:        decision.reason
          )
        else
          @logger.warn { "[CyberArmor] Policy DENIED (monitor mode — allowing): #{decision.reason}" }
          return Policy::Decision.new(
            allowed:         true,
            decision_type:   decision.decision_type,
            reason:          decision.reason,
            redacted_prompt: decision.redacted_prompt
          )
        end
      end

      decision
    end

    # Emit an audit event to the audit service.
    #
    # @param event [Hash] arbitrary audit payload
    # @return [void]
    def emit_audit(event:)
      return unless @audit_url

      begin
        post('/audit/events', event, base_url: @audit_url)
      rescue => e
        # Audit emission failures are non-fatal; log and continue.
        @logger.error { "[CyberArmor] Audit emission failed: #{e.message}" }
      end
    end

    private

    # Resolve and validate the control plane URL.
    def resolve_url(provided)
      url = provided || ENV['CYBERARMOR_URL']
      raise ArgumentError, 'CYBERARMOR_URL is required' if url.nil? || url.empty?

      url.chomp('/')
    end

    # Resolve a boolean from a provided value or a string env var.
    def resolve_bool(provided, env_string)
      return provided unless provided.nil?

      env_string.to_s.downcase == 'true'
    end

    def validate_enforce_mode!
      unless %w[enforce monitor].include?(@enforce_mode)
        raise ArgumentError, "Invalid enforce_mode '#{@enforce_mode}'. Must be 'enforce' or 'monitor'."
      end
    end

    # Perform a signed POST request to the given path.
    #
    # @param path     [String]  URL path including leading slash
    # @param body     [Hash]    request body (will be JSON-encoded)
    # @param base_url [String]  override the default control-plane URL
    # @return [Hash]  parsed JSON response body
    def post(path, body, base_url: nil)
      target = base_url || @url
      uri    = URI.parse("#{target}#{path}")

      body_json = JSON.generate(body)
      signature = sign_request(body_json)

      http           = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl   = uri.scheme == 'https'
      http.open_timeout = DEFAULT_OPEN_TIMEOUT
      http.read_timeout = @timeout

      request = Net::HTTP::Post.new(uri.request_uri)
      request['Content-Type']      = 'application/json'
      request['Accept']            = 'application/json'
      request['X-CyberArmor-Agent'] = @agent_id
      request['X-CyberArmor-Sig']  = signature
      request.body = body_json

      response = http.request(request)

      unless response.is_a?(Net::HTTPSuccess)
        raise "HTTP #{response.code}: #{response.body}"
      end

      JSON.parse(response.body)
    end

    # HMAC-SHA256 signature over the JSON body using the agent secret.
    def sign_request(body_json)
      require 'openssl'
      digest    = OpenSSL::Digest.new('sha256')
      hmac      = OpenSSL::HMAC.hexdigest(digest, @agent_secret, body_json)
      hmac
    end

    # Handle a failure to reach the control plane according to fail_open policy.
    #
    # @param error  [Exception]
    # @param prompt [String]
    # @return [CyberArmor::Policy::Decision]
    def handle_control_plane_failure(error, prompt)
      @logger.error { "[CyberArmor] Control plane unreachable: #{error.message}" }

      if @fail_open
        @logger.warn { "[CyberArmor] fail_open=true — allowing request despite control plane failure" }
        Policy::Decision.new(
          allowed:         true,
          decision_type:   'ALLOW',
          reason:          "Control plane unreachable; fail_open=true",
          redacted_prompt: nil
        )
      else
        if enforce_mode == 'enforce'
          raise Policy::PolicyViolationError.new(
            decision_type: 'DENY',
            reason:        "Control plane unreachable and fail_open=false: #{error.message}"
          )
        else
          @logger.warn { "[CyberArmor] Control plane unreachable (monitor mode — allowing)" }
          Policy::Decision.new(
            allowed:         true,
            decision_type:   'DENY',
            reason:          "Control plane unreachable (monitor mode)",
            redacted_prompt: nil
          )
        end
      end
    end
  end
end
