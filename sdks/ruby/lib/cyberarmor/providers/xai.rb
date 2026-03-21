# frozen_string_literal: true

module CyberArmor
  module Providers
    class XAI < OpenAICompatible
      def initialize(client:, openai:, tenant_id:, model: 'grok-3')
        super(client: client, openai: openai, tenant_id: tenant_id, provider: 'xai', model: model)
      end
    end
  end
end

