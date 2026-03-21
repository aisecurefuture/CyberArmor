# frozen_string_literal: true

module CyberArmor
  module Providers
    class Meta < OpenAICompatible
      def initialize(client:, openai:, tenant_id:, model: 'llama-3.3-70b-instruct')
        super(client: client, openai: openai, tenant_id: tenant_id, provider: 'meta', model: model)
      end
    end
  end
end

