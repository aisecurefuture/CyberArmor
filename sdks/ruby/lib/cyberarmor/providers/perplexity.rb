# frozen_string_literal: true

module CyberArmor
  module Providers
    class Perplexity < OpenAICompatible
      def initialize(client:, openai:, tenant_id:, model: 'sonar')
        super(client: client, openai: openai, tenant_id: tenant_id, provider: 'perplexity', model: model)
      end
    end
  end
end

