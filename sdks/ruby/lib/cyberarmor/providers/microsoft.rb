# frozen_string_literal: true

module CyberArmor
  module Providers
    class Microsoft < OpenAICompatible
      def initialize(client:, openai:, tenant_id:, model: 'phi-4')
        super(client: client, openai: openai, tenant_id: tenant_id, provider: 'microsoft', model: model)
      end
    end
  end
end

