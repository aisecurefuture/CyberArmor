# frozen_string_literal: true

module CyberArmor
  module Providers
    # Wraps the `anthropic-sdk-ruby` gem (https://github.com/anthropics/anthropic-sdk-ruby)
    # with CyberArmor policy enforcement and audit emission.
    #
    # The underlying gem must be installed separately:
    #   gem 'anthropic', '~> 0.3'
    #
    # Usage:
    #   cyberarmor = CyberArmor::Client.new
    #   anthropic_raw = Anthropic::Client.new(api_key: ENV['ANTHROPIC_API_KEY'])
    #
    #   protected = CyberArmor::Providers::Anthropic.new(
    #     client:    cyberarmor,
    #     anthropic: anthropic_raw,
    #     tenant_id: "acme-corp"
    #   )
    #
    #   response = protected.messages(
    #     model:      "claude-opus-4-6",
    #     max_tokens: 1024,
    #     messages:   [{ role: "user", content: "Hello, Claude" }]
    #   )
    class Anthropic
      # @param client    [CyberArmor::Client]   the policy/audit client
      # @param anthropic [Anthropic::Client]     an initialised anthropic SDK client
      # @param tenant_id [String]                tenant scope for policy evaluation
      # @param model     [String]                default model fallback
      def initialize(client:, anthropic:, tenant_id:, model: nil)
        @cyberarmor     = client
        @anthropic      = anthropic
        @tenant_id      = tenant_id
        @default_model  = model
      end

      # Check policy, then call Anthropic's messages endpoint.
      #
      # @param model      [String]  Anthropic model id, e.g. "claude-opus-4-6"
      # @param max_tokens [Integer] maximum tokens in the response
      # @param messages   [Array]   array of message hashes with :role and :content
      # @param kwargs     [Hash]    any additional parameters forwarded to the SDK
      # @return [Anthropic::Message] the API response object
      # @raise [CyberArmor::Policy::PolicyViolationError] if denied in enforce mode
      def messages(model: nil, max_tokens: 1024, messages: [], **kwargs)
        resolved_model = model || @default_model || 'claude-opus-4-6'
        prompt         = extract_prompt(messages)

        decision = @cyberarmor.check_policy(
          prompt:    prompt,
          model:     resolved_model,
          provider:  'anthropic',
          tenant_id: @tenant_id
        )

        resolved_messages = messages
        if decision.decision_type == 'ALLOW_WITH_REDACTION' && decision.redacted_prompt
          resolved_messages = apply_redaction(messages, decision.redacted_prompt)
        end

        started_at = Time.now

        begin
          response = @anthropic.messages(
            model:      resolved_model,
            max_tokens: max_tokens,
            messages:   resolved_messages,
            **kwargs
          )
        rescue => e
          emit_audit_event(
            event_type:  'completion_error',
            model:       resolved_model,
            prompt:      prompt,
            decision:    decision,
            error:       e.message,
            duration_ms: elapsed_ms(started_at)
          )
          raise
        end

        emit_audit_event(
          event_type:   'completion_returned',
          model:        resolved_model,
          prompt:       prompt,
          decision:     decision,
          response_id:  response.respond_to?(:id) ? response.id : nil,
          stop_reason:  response.respond_to?(:stop_reason) ? response.stop_reason : nil,
          input_tokens: response.respond_to?(:usage) ? response.usage&.input_tokens : nil,
          output_tokens: response.respond_to?(:usage) ? response.usage&.output_tokens : nil,
          duration_ms:  elapsed_ms(started_at)
        )

        response
      end

      private

      def extract_prompt(messages)
        messages
          .select  { |m| (m[:role] || m['role']) == 'user' }
          .map     { |m| m[:content] || m['content'] || '' }
          .join("\n")
      end

      def apply_redaction(messages, redacted_prompt)
        messages = messages.dup
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
        messages
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
