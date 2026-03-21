<?php

declare(strict_types=1);

namespace CyberArmor\Policy;

/**
 * Immutable value object representing a policy engine decision.
 */
final class Decision
{
    /**
     * All decision types the policy engine may return.
     */
    public const DECISION_TYPES = [
        'ALLOW',
        'DENY',
        'ALLOW_WITH_REDACTION',
        'ALLOW_WITH_LIMITS',
        'REQUIRE_APPROVAL',
        'ALLOW_WITH_AUDIT_ONLY',
        'QUARANTINE',
    ];

    /**
     * @param bool        $allowed        Whether the request may proceed.
     * @param string      $decisionType   One of {@see self::DECISION_TYPES}.
     * @param string      $reason         Human-readable explanation.
     * @param string|null $redactedPrompt Prompt after PII/secrets removal, or null.
     */
    public function __construct(
        public readonly bool    $allowed,
        public readonly string  $decisionType,
        public readonly string  $reason,
        public readonly ?string $redactedPrompt = null,
    ) {}

    /**
     * Build a Decision from a decoded JSON array returned by the policy API.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            allowed:        (bool) ($data['allowed'] ?? false),
            decisionType:   (string) ($data['decision_type'] ?? 'DENY'),
            reason:         (string) ($data['reason'] ?? ''),
            redactedPrompt: isset($data['redacted_prompt']) ? (string) $data['redacted_prompt'] : null,
        );
    }

    /**
     * Convenience predicate.
     */
    public function isAllowed(): bool
    {
        return $this->allowed;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'allowed'         => $this->allowed,
            'decision_type'   => $this->decisionType,
            'reason'          => $this->reason,
            'redacted_prompt' => $this->redactedPrompt,
        ];
    }
}
