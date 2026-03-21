<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;
use CyberArmor\Policy\PolicyViolationException;

/**
 * Wraps the Anthropic PHP SDK (or direct HTTP) with CyberArmor policy
 * enforcement and audit emission.
 *
 * This provider supports two modes:
 *   1. If an Anthropic SDK client object is supplied (via $anthropic), it
 *      delegates to that object's messages()->create() method.
 *   2. Otherwise it calls the Anthropic Messages API directly via cURL.
 *
 * Usage (with SDK):
 *   $cyberarmor = new \CyberArmor\Client();
 *   // Using anthropic-php or a compatible client
 *   $rawAnthropic = new \Anthropic\Client(apiKey: getenv('ANTHROPIC_API_KEY'));
 *
 *   $ai = new \CyberArmor\Providers\Anthropic(
 *       client:    $cyberarmor,
 *       apiKey:    getenv('ANTHROPIC_API_KEY'),
 *       tenantId:  'acme-corp'
 *   );
 *   $response = $ai->messages(
 *       messages: [['role' => 'user', 'content' => 'Hello Claude']],
 *       model:    'claude-opus-4-6'
 *   );
 */
final class Anthropic
{
    private const ANTHROPIC_API_BASE    = 'https://api.anthropic.com';
    private const ANTHROPIC_API_VERSION = '2023-06-01';
    private const SDK_VERSION           = '2.0.0';
    private const TIMEOUT_SEC           = 30;

    /**
     * @param Client      $client    The CyberArmor policy/audit client.
     * @param string      $apiKey    Anthropic API key.
     * @param string      $tenantId  Tenant scope for policy evaluation.
     * @param string      $model     Default model.
     * @param object|null $anthropic Optional pre-built Anthropic SDK client.
     */
    public function __construct(
        private readonly Client  $client,
        private readonly string  $apiKey,
        private readonly string  $tenantId,
        private readonly string  $model     = 'claude-opus-4-6',
        private readonly ?object $anthropic = null,
    ) {}

    /**
     * Check policy then call the Anthropic Messages API.
     *
     * @param array<array{role: string, content: string}> $messages
     * @param string|null                                  $model       Override default model.
     * @param int                                          $maxTokens   Maximum tokens.
     * @param string|null                                  $system      Optional system prompt.
     * @param array<string, mixed>                         $options     Additional parameters.
     *
     * @return array<string, mixed>  Decoded API response.
     * @throws PolicyViolationException  When the policy engine denies the request.
     */
    public function messages(
        array   $messages,
        ?string $model     = null,
        int     $maxTokens = 1024,
        ?string $system    = null,
        array   $options   = [],
    ): array {
        $resolvedModel    = $model ?? $this->model;
        $prompt           = $this->extractPrompt($messages);

        $decision = $this->client->checkPolicy($prompt, $resolvedModel, 'anthropic', $this->tenantId);

        $resolvedMessages = $messages;
        if ($decision->decisionType === 'ALLOW_WITH_REDACTION' && $decision->redactedPrompt !== null) {
            $resolvedMessages = $this->applyRedaction($messages, $decision->redactedPrompt);
        }

        $params = array_merge($options, [
            'model'      => $resolvedModel,
            'max_tokens' => $maxTokens,
            'messages'   => $resolvedMessages,
        ]);
        if ($system !== null) {
            $params['system'] = $system;
        }

        $startTime = microtime(true);

        try {
            $response = $this->anthropic !== null
                ? $this->callViaSdk($params)
                : $this->callViaCurl($params);
        } catch (PolicyViolationException $e) {
            throw $e;
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

        $this->emitAudit('completion_returned', [
            'model'         => $resolvedModel,
            'prompt'        => $prompt,
            'decision'      => $decision->toArray(),
            'response_id'   => $response['id'] ?? null,
            'stop_reason'   => $response['stop_reason'] ?? null,
            'input_tokens'  => $response['usage']['input_tokens'] ?? null,
            'output_tokens' => $response['usage']['output_tokens'] ?? null,
            'duration_ms'   => $this->elapsedMs($startTime),
        ]);

        return $response;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Delegate to an injected Anthropic SDK client.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    private function callViaSdk(array $params): array
    {
        // anthropic-php/client: $anthropic->messages()->create($params)
        $result = $this->anthropic->messages()->create($params);
        return is_array($result) ? $result : (array) $result;
    }

    /**
     * Call the Anthropic API directly via cURL.
     *
     * @param array<string, mixed> $params
     * @return array<string, mixed>
     */
    private function callViaCurl(array $params): array
    {
        $url      = self::ANTHROPIC_API_BASE . '/v1/messages';
        $bodyJson = json_encode($params, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $bodyJson,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT_SEC,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
                'x-api-key: ' . $this->apiKey,
                'anthropic-version: ' . self::ANTHROPIC_API_VERSION,
                'anthropic-sdk: cyberarmor-php/' . self::SDK_VERSION,
            ],
        ]);

        $responseBody = curl_exec($ch);
        $httpCode     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError    = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false || $curlError !== '') {
            throw new \RuntimeException('Anthropic HTTP request failed: ' . $curlError);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException(sprintf('Anthropic HTTP %d: %s', $httpCode, $responseBody));
        }

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode((string) $responseBody, true, 512, JSON_THROW_ON_ERROR);
        return $decoded;
    }

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
            'sdk_version' => self::SDK_VERSION,
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
