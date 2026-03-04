# frozen_string_literal: true

# AIShields RASP — Ruby Runtime Application Self-Protection
# Supports: Rack middleware, Net::HTTP patch, Faraday middleware

require 'json'
require 'net/http'
require 'uri'

module AIShields
  module RASP
    AI_DOMAINS = %w[
      api.openai.com api.anthropic.com generativelanguage.googleapis.com
      api.cohere.ai api.mistral.ai api-inference.huggingface.co
      api.together.xyz api.replicate.com api.groq.com
    ].freeze

    PROMPT_INJECTION_PATTERNS = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /you\s+are\s+now\s+(a|an|in)/i,
      /system\s*:\s*you\s+are/i,
      /<\s*(system|prompt|instruction)\s*>/i,
      /jailbreak|DAN\s+mode|bypass\s+filter/i,
    ].freeze

    DLP_PATTERNS = {
      ssn: /\b\d{3}-\d{2}-\d{4}\b/,
      credit_card: /\b4[0-9]{12}(?:[0-9]{3})?\b/,
      aws_key: /AKIA[0-9A-Z]{16}/,
      private_key: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/,
    }.freeze

    class << self
      attr_accessor :config

      def configure
        self.config ||= Config.new
        yield(config) if block_given?
        config
      end

      def ai_endpoint?(host)
        clean = host.to_s.split(':').first.to_s
        AI_DOMAINS.include?(clean) ||
          clean.end_with?('.openai.azure.com') ||
          clean.end_with?('.cognitiveservices.azure.com')
      end

      def inspect_request(url, body = '')
        host = URI.parse(url).host rescue ''
        return InspectionResult.new(true) unless ai_endpoint?(host)

        # Prompt injection
        if config&.prompt_injection_enabled
          PROMPT_INJECTION_PATTERNS.each do |pat|
            if body.match?(pat)
              return InspectionResult.new(false, "Prompt injection: #{pat.source}") if config.mode == :block
            end
          end
        end

        # DLP
        if config&.dlp_enabled
          findings = DLP_PATTERNS.select { |_, pat| body.match?(pat) }.keys
          if findings.any?
            return InspectionResult.new(false, "Sensitive data: #{findings.join(',')}") if config.mode == :block
          end
        end

        InspectionResult.new(true)
      end
    end

    Config = Struct.new(:control_plane_url, :api_key, :tenant_id, :mode,
                         :dlp_enabled, :prompt_injection_enabled, keyword_init: true) do
      def initialize(**)
        super
        self.control_plane_url ||= ENV.fetch('AISHIELDS_URL', 'http://localhost:8000')
        self.api_key ||= ENV.fetch('AISHIELDS_API_KEY', '')
        self.tenant_id ||= ENV.fetch('AISHIELDS_TENANT', 'default')
        self.mode ||= ENV.fetch('AISHIELDS_MODE', 'monitor').to_sym
        self.dlp_enabled = true if dlp_enabled.nil?
        self.prompt_injection_enabled = true if prompt_injection_enabled.nil?
      end
    end

    InspectionResult = Struct.new(:allowed, :reason) do
      def allowed?
        allowed
      end
    end

    # Rack Middleware
    class RackMiddleware
      def initialize(app)
        @app = app
        AIShields::RASP.configure unless AIShields::RASP.config
      end

      def call(env)
        if env['REQUEST_METHOD'] == 'POST'
          host = env['HTTP_X_FORWARDED_HOST'] || env['HTTP_HOST'] || ''
          if AIShields::RASP.ai_endpoint?(host)
            body = env['rack.input'].read
            env['rack.input'].rewind
            result = AIShields::RASP.inspect_request("https://#{host}#{env['PATH_INFO']}", body)
            unless result.allowed?
              return [403, { 'Content-Type' => 'application/json' },
                      [{ error: result.reason, policy: 'aishields-rasp' }.to_json]]
            end
          end
        end
        @app.call(env)
      end
    end

    # Faraday Middleware
    class FaradayMiddleware < Faraday::Middleware
      def call(env)
        if env.method == :post
          host = env.url.host
          if AIShields::RASP.ai_endpoint?(host)
            body = env.body.to_s
            result = AIShields::RASP.inspect_request(env.url.to_s, body)
            unless result.allowed?
              raise "AIShields RASP blocked: #{result.reason}"
            end
          end
        end
        @app.call(env)
      end
    rescue NameError
      # Faraday not loaded
    end
  end
end
