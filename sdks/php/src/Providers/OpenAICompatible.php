<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;

class OpenAICompatible
{
    public function __construct(
        protected readonly Client $client,
        protected readonly object $openai,
        protected readonly string $tenantId,
        protected readonly string $provider,
        protected readonly string $model = 'gpt-4o-mini',
    ) {}

    public function chat(array $messages, ?string $model = null, array $options = []): array
    {
        $resolvedModel = $model ?? $this->model;
        $prompt = implode("\n", array_values(array_map(
            fn(array $m): string => (string) ($m['content'] ?? ''),
            array_filter($messages, fn(array $m): bool => (($m['role'] ?? '') === 'user'))
        )));

        $decision = $this->client->checkPolicy($prompt, $resolvedModel, $this->provider, $this->tenantId);
        if ($decision->decisionType === 'ALLOW_WITH_REDACTION' && $decision->redactedPrompt !== null) {
            for ($i = count($messages) - 1; $i >= 0; $i--) {
                if (($messages[$i]['role'] ?? '') === 'user') {
                    $messages[$i]['content'] = $decision->redactedPrompt;
                    break;
                }
            }
        }

        $startTime = microtime(true);
        $response = $this->openai->chat()->create(array_merge($options, [
            'model' => $resolvedModel,
            'messages' => $messages,
        ]));
        $responseArray = is_array($response) ? $response : (array) $response;

        $this->client->emitAudit([
            'agent_id' => $this->client->getAgentId(),
            'tenant_id' => $this->tenantId,
            'event_type' => 'completion_returned',
            'timestamp' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z'),
            'sdk_version' => '2.0.0',
            'sdk_lang' => 'php',
            'payload' => [
                'provider' => $this->provider,
                'model' => $resolvedModel,
                'duration_ms' => (int) round((microtime(true) - $startTime) * 1000),
                'response_id' => $responseArray['id'] ?? null,
            ],
        ]);

        return $responseArray;
    }
}
