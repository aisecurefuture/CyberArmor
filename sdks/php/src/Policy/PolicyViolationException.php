<?php

declare(strict_types=1);

namespace CyberArmor\Policy;

/**
 * Thrown when the CyberArmor policy engine denies a request and the SDK is
 * operating in "enforce" mode.
 */
final class PolicyViolationException extends \RuntimeException
{
    /**
     * @param string $decisionType One of Decision::DECISION_TYPES.
     * @param string $reason       Human-readable explanation from the policy engine.
     * @param int    $code         Optional exception code.
     */
    public function __construct(
        private readonly string $decisionType,
        private readonly string $reason,
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct(
            sprintf('CyberArmor policy violation [%s]: %s', $decisionType, $reason),
            $code,
            $previous,
        );
    }

    /**
     * The decision type that caused the violation.
     */
    public function getDecisionType(): string
    {
        return $this->decisionType;
    }

    /**
     * The human-readable reason from the policy engine.
     */
    public function getPolicyReason(): string
    {
        return $this->reason;
    }
}
