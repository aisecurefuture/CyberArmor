# frozen_string_literal: true

# CyberArmor AI Identity Control Plane SDK for Ruby
# Provides policy enforcement and audit capabilities for AI workloads.
#
# Usage:
#   require 'cyberarmor'
#
#   client = CyberArmor::Client.new
#   decision = client.check_policy(
#     prompt:    "Tell me about AI security",
#     model:     "gpt-4o",
#     provider:  "openai",
#     tenant_id: "tenant-abc"
#   )

require_relative 'cyberarmor/version'
require_relative 'cyberarmor/policy'
require_relative 'cyberarmor/audit'
require_relative 'cyberarmor/client'
require_relative 'cyberarmor/providers/openai'
require_relative 'cyberarmor/providers/anthropic'
require_relative 'cyberarmor/providers/openai_compatible'
require_relative 'cyberarmor/providers/google'
require_relative 'cyberarmor/providers/amazon'
require_relative 'cyberarmor/providers/microsoft'
require_relative 'cyberarmor/providers/xai'
require_relative 'cyberarmor/providers/meta'
require_relative 'cyberarmor/providers/perplexity'

module CyberArmor
  # Convenience method to build a Client from environment variables.
  #
  # @return [CyberArmor::Client]
  def self.client
    @client ||= Client.new
  end

  # Reset the memoized default client (useful in tests).
  def self.reset_client!
    @client = nil
  end
end
