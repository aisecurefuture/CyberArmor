# frozen_string_literal: true

module CyberArmor
  # Policy module provides decision types, the Decision value object, and
  # the error raised when a request is denied in enforce mode.
  module Policy
    # All possible decision types returned by the CyberArmor policy engine.
    DECISION_TYPES = %w[
      ALLOW
      DENY
      ALLOW_WITH_REDACTION
      ALLOW_WITH_LIMITS
      REQUIRE_APPROVAL
      ALLOW_WITH_AUDIT_ONLY
      QUARANTINE
    ].freeze

    # Raised when the policy engine denies a request and the SDK is operating
    # in "enforce" mode.
    class PolicyViolationError < StandardError
      attr_reader :decision_type, :reason

      # @param decision_type [String] one of DECISION_TYPES
      # @param reason [String] human-readable explanation from the policy engine
      def initialize(decision_type:, reason:)
        @decision_type = decision_type
        @reason        = reason
        super("CyberArmor policy violation [#{decision_type}]: #{reason}")
      end
    end

    # Immutable value object representing a policy engine decision.
    Decision = Struct.new(
      :allowed,          # [Boolean] true when the request may proceed
      :decision_type,    # [String]  one of DECISION_TYPES
      :reason,           # [String]  human-readable explanation
      :redacted_prompt,  # [String, nil] prompt after PII/secrets are removed
      keyword_init: true
    ) do
      # Convenience predicate.
      # @return [Boolean]
      def allowed?
        allowed == true
      end

      # Build a Decision from a parsed JSON hash returned by the policy API.
      #
      # @param hash [Hash]
      # @return [Decision]
      def self.from_hash(hash)
        new(
          allowed:         hash.fetch('allowed', false),
          decision_type:   hash.fetch('decision_type', 'DENY'),
          reason:          hash.fetch('reason', ''),
          redacted_prompt: hash['redacted_prompt']
        )
      end
    end
  end
end
