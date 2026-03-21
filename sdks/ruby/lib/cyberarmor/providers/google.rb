# frozen_string_literal: true

module CyberArmor
  module Providers
    class Google < OpenAICompatible
      def initialize(client:, openai:, tenant_id:, model: 'gemini-2.0-flash')
        super(client: client, openai: openai, tenant_id: tenant_id, provider: 'google', model: model)
      end
    end
  end
end

