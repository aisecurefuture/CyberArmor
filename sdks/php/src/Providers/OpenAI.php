<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;
use CyberArmor\Policy\Decision;
use CyberArmor\Policy\PolicyViolationException;

/**
 * Wraps the openai-php/client library with CyberArmor policy enforcement and
 * audit emission.
 *
 * The underlying library must be installed separately:
 *   composer require openai-php/client
 *
 * Usage:
 *   $cyberarmor = new \CyberArmor\Client();
 *   $rawOpenAI  = \OpenAI::client(getenv('OPENAI_API_KEY'));
 *
 *   $ai = new \CyberArmor\Providers\OpenAI(
 *       client:   $cyberarmor,
 *       openai:   $rawOpenAI,
 *       tenantId: 'acme-corp'
 *   );
 *
 *   $response = $ai->chat(
 *       messages: [['role' => 'user', 'content' => 'Hello AI']],
 *       model:    'gpt-4o'
 *   );
 */
final class OpenAI
{
    /**
     * @param Client $client    The CyberArmor policy/audit client.
     * @param object $openai    An initialised openai-php/client instance.
     * @param string $tenantId  Tenant scope for policy evaluation.
     * @param string $model     Default model to use when not specified per-call.
     */
    public function __construct(
        private readonly Client $client,
        private readonly object $openai,
        private readonly string $tenantId,
        private readonly string $model = 'gpt-4o',
    ) {}

    /**
     * Check policy then forward the chat completion request to OpenAI.
     *
     * @param array<array{role: string, content: string}> $messages
     * @param string|null                                  $model    Override default model.
     * @param array<string, mixed>                         $options  Additional parameters.
     *
     * @return array<string, mixed>  Decoded OpenAI response.
     * @throws PolicyViolationException  When the policy engine denies the request.
     */
    public function chat(
        array   $messages,
        ?string $model   = null,
        array   $options = [],
    ): array {
        $resolvedModel = $model ?? $this->model;
        $prompt        = $this->extractPrompt($messages);

        $decision = $this->client->checkPolicy($prompt, $resolvedModel, 'openai', $this->tenantId);

        $resolvedMessages = $messages;
        if ($decision->decisionType === 'ALLOW_WITH_REDACTION' && $decision->redactedPrompt !== null) {
            $resolvedMessages = $this->applyRedaction($messages, $decision->redactedPrompt);
        }

        $params = array_merge($options, [
            'model'    => $resolvedModel,
            'messages' => $resolvedMessages,
        ]);

        $startTime = microtime(true);

        try {
            // openai-php/client: $openai->chat()->create($params)
            $response = $this->openai->chat()->create($params);
        } catch (\Throwable $e) {
            $this->emitAudit('completion_error', [
                'model'       => $resolvedModel,
                'prompt'      => $prompt,
                'decision'    => $decision->toArray(),
                'error'       => $e->getMessage(),
                'duration_ms' => $this->elapsedMs($startTime),
            ]);
            throw $e;
        }

        // Convert to array if the SDK returns an object/DTO.
        $responseArray = is_array($response) ? $response : (array) $response;

        $this->emitAudit('completion_returned', [
            'model'       => $resolvedModel,
            'prompt'      => $prompt,
            'decision'    => $decision->toArray(),
            'response_id' => $responseArray['id'] ?? null,
            'usage'       => $responseArray['usage'] ?? null,
            'duration_ms' => $this->elapsedMs($startTime),
        ]);

        return $responseArray;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * @param array<array{role: string, content: string}> $messages
     */
    private function extractPrompt(array $messages): string
    {
        $parts = [];
        foreach ($messages as $msg) {
            if (($msg['role'] ?? '') === 'user') {
                $parts[] = $msg['content'] ?? '';
            }
        }
        return implode("\n", $parts);
    }

    /**
     * Replace the last user message with the redacted prompt.
     *
     * @param array<array{role: string, content: string}> $messages
     * @return array<array{role: string, content: string}>
     */
    private function applyRedaction(array $messages, string $redactedPrompt): array
    {
        $lastUserIdx = null;
        foreach (array_reverse(array_keys($messages)) as $idx) {
            if (($messages[$idx]['role'] ?? '') === 'user') {
                $lastUserIdx = $idx;
                break;
            }
        }

        if ($lastUserIdx !== null) {
            $messages[$lastUserIdx]['content'] = $redactedPrompt;
        }

        return $messages;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function emitAudit(string $eventType, array $payload): void
    {
        $event = [
            'agent_id'    => $this->client->getAgentId(),
            'tenant_id'   => $this->tenantId,
            'event_type'  => $eventType,
            'timestamp'   => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z'),
            'sdk_version' => '2.0.0',
            'sdk_lang'    => 'php',
            'payload'     => $payload,
        ];

        $this->client->emitAudit($event);
    }

    private function elapsedMs(float $startTime): int
    {
        return (int) round((microtime(true) - $startTime) * 1000);
    }
}
