# frozen_string_literal: true

module CyberArmor
  module Providers
    class Amazon < OpenAICompatible
      def initialize(client:, openai:, tenant_id:, model: 'amazon.nova-lite-v1:0')
        super(client: client, openai: openai, tenant_id: tenant_id, provider: 'amazon', model: model)
      end
    end
  end
end

