# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'
require 'time'

module CyberArmor
  # Thin wrapper around audit event emission.
  # Used internally by Client#emit_audit.
  module Audit
    # Build a standardized audit event hash.
    #
    # @param agent_id   [String]
    # @param tenant_id  [String]
    # @param event_type [String]  e.g. "policy_evaluated", "completion_returned"
    # @param payload    [Hash]    arbitrary event-specific data
    # @return [Hash]
    def self.build_event(agent_id:, tenant_id:, event_type:, payload: {})
      {
        agent_id:    agent_id,
        tenant_id:   tenant_id,
        event_type:  event_type,
        timestamp:   Time.now.utc.iso8601(3),
        sdk_version: CyberArmor::VERSION,
        sdk_lang:    'ruby',
        payload:     payload
      }
    end
  end
end
