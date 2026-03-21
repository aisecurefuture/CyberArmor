# frozen_string_literal: true

module CyberArmor
  module Providers
    # Wraps the `openai` Ruby gem (https://github.com/alexrudall/ruby-openai) with
    # CyberArmor policy enforcement and audit emission.
    #
    # The underlying openai gem must be installed separately:
    #   gem 'ruby-openai', '~> 7.0'
    #
    # Usage:
    #   cyberarmor = CyberArmor::Client.new
    #   openai_raw = OpenAI::Client.new(access_token: ENV['OPENAI_API_KEY'])
    #
    #   protected_openai = CyberArmor::Providers::OpenAI.new(
    #     client:    cyberarmor,
    #     openai:    openai_raw,
    #     tenant_id: "acme-corp"
    #   )
    #
    #   response = protected_openai.chat(parameters: {
    #     model:    "gpt-4o",
    #     messages: [{ role: "user", content: "Explain post-quantum cryptography" }]
    #   })
    class OpenAI
      # @param client    [CyberArmor::Client]  the policy/audit client
      # @param openai    [OpenAI::Client]       an initialised ruby-openai client
      # @param tenant_id [String]               tenant scope for policy evaluation
      # @param model     [String]               default model override
      def initialize(client:, openai:, tenant_id:, model: nil)
        @cyberarmor = client
        @openai     = openai
        @tenant_id  = tenant_id
        @default_model = model
      end

      # Check policy then forward the chat completion request to OpenAI.
      #
      # @param parameters [Hash] passed directly to openai gem's chat method;
      #   must include :messages (Array) and optionally :model.
      # @return [Hash] the OpenAI API response
      # @raise [CyberArmor::Policy::PolicyViolationError] if denied in enforce mode
      def chat(parameters:)
        params    = parameters.dup
        model     = params[:model] || params['model'] || @default_model || 'gpt-4o'
        messages  = params[:messages] || params['messages'] || []
        prompt    = extract_prompt(messages)

        decision = @cyberarmor.check_policy(
          prompt:    prompt,
          model:     model,
          provider:  'openai',
          tenant_id: @tenant_id
        )

        # If the policy engine redacted the prompt, substitute it.
        if decision.decision_type == 'ALLOW_WITH_REDACTION' && decision.redacted_prompt
          params = apply_redaction(params, decision.redacted_prompt)
        end

        started_at = Time.now

        begin
          response = @openai.chat(parameters: params)
        rescue => e
          emit_audit_event(
            event_type: 'completion_error',
            model:      model,
            prompt:     prompt,
            decision:   decision,
            error:      e.message,
            duration_ms: elapsed_ms(started_at)
          )
          raise
        end

        emit_audit_event(
          event_type:  'completion_returned',
          model:       model,
          prompt:      prompt,
          decision:    decision,
          response_id: response.dig('id'),
          usage:       response.dig('usage'),
          duration_ms: elapsed_ms(started_at)
        )

        response
      end

      private

      # Extract a single string from the messages array for policy evaluation.
      # Concatenates all user-role message content.
      def extract_prompt(messages)
        messages
          .select  { |m| (m[:role] || m['role']) == 'user' }
          .map     { |m| m[:content] || m['content'] || '' }
          .join("\n")
      end

      # Replace the last user message content with the redacted prompt.
      def apply_redaction(params, redacted_prompt)
        messages = (params[:messages] || params['messages'] || []).dup
        last_user_idx = messages.rindex { |m| (m[:role] || m['role']) == 'user' }
        if last_user_idx
          msg = messages[last_user_idx].dup
          if msg.key?(:content)
            msg[:content] = redacted_prompt
          else
            msg['content'] = redacted_prompt
          end
          messages[last_user_idx] = msg
        end
        params.merge(messages: messages)
      end

      def emit_audit_event(event_type:, **payload)
        event = CyberArmor::Audit.build_event(
          agent_id:   @cyberarmor.agent_id,
          tenant_id:  @tenant_id,
          event_type: event_type,
          payload:    payload.transform_keys(&:to_s)
        )
        @cyberarmor.emit_audit(event: event)
      end

      def elapsed_ms(started_at)
        ((Time.now - started_at) * 1000).round
      end
    end
  end
end
