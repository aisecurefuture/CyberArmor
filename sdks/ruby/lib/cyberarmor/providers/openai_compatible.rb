# frozen_string_literal: true

module CyberArmor
  module Providers
    class OpenAICompatible
      def initialize(client:, openai:, tenant_id:, provider:, model: nil)
        @cyberarmor = client
        @openai = openai
        @tenant_id = tenant_id
        @provider = provider
        @default_model = model
      end

      def chat(parameters:)
        params = parameters.dup
        model = params[:model] || params['model'] || @default_model || 'gpt-4o-mini'
        messages = params[:messages] || params['messages'] || []
        prompt = messages.select { |m| (m[:role] || m['role']) == 'user' }
                         .map { |m| m[:content] || m['content'] || '' }
                         .join("\n")

        decision = @cyberarmor.check_policy(
          prompt: prompt,
          model: model,
          provider: @provider,
          tenant_id: @tenant_id
        )

        if decision.decision_type == 'ALLOW_WITH_REDACTION' && decision.redacted_prompt
          last_user_idx = messages.rindex { |m| (m[:role] || m['role']) == 'user' }
          if last_user_idx
            msg = messages[last_user_idx].dup
            if msg.key?(:content)
              msg[:content] = decision.redacted_prompt
            else
              msg['content'] = decision.redacted_prompt
            end
            messages[last_user_idx] = msg
            params = params.merge(messages: messages)
          end
        end

        started_at = Time.now
        response = @openai.chat(parameters: params)
        @cyberarmor.emit_audit(event: CyberArmor::Audit.build_event(
          agent_id: @cyberarmor.agent_id,
          tenant_id: @tenant_id,
          event_type: 'completion_returned',
          payload: {
            'provider' => @provider,
            'model' => model,
            'duration_ms' => ((Time.now - started_at) * 1000).round,
            'response_id' => response.dig('id')
          }
        ))
        response
      end
    end
  end
end

