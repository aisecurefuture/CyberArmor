# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../../lib/cyberarmor'

class OpenAICompatibleProviderTest < Minitest::Test
  Decision = Struct.new(:decision_type, :redacted_prompt)

  class FakeCyberArmor
    attr_reader :checked, :events

    def initialize(decision)
      @decision = decision
      @checked = []
      @events = []
    end

    def check_policy(prompt:, model:, provider:, tenant_id:)
      @checked << { prompt: prompt, model: model, provider: provider, tenant_id: tenant_id }
      @decision
    end

    def emit_audit(event:)
      @events << event
    end

    def agent_id
      'agt_test'
    end
  end

  class FakeOpenAI
    attr_reader :received

    def initialize
      @received = nil
    end

    def chat(parameters:)
      @received = parameters
      { 'id' => 'resp_123', 'choices' => [] }
    end
  end

  def test_openai_compatible_uses_policy_and_emits_audit
    decision = Decision.new('ALLOW_WITH_REDACTION', 'safe text')
    ca = FakeCyberArmor.new(decision)
    openai = FakeOpenAI.new

    provider = CyberArmor::Providers::Google.new(
      client: ca,
      openai: openai,
      tenant_id: 'tenant_a',
      model: 'gemini-2.0-flash'
    )

    resp = provider.chat(parameters: {
      model: 'gemini-2.0-flash',
      messages: [
        { role: 'system', content: 'sys' },
        { role: 'user', content: 'secret prompt' }
      ]
    })

    assert_equal 'resp_123', resp['id']
    assert_equal 'google', ca.checked[0][:provider]
    assert_equal 'safe text', openai.received[:messages].last[:content]
    assert_equal 1, ca.events.size
    assert_equal 'completion_returned', ca.events[0][:event_type]
  end
end

