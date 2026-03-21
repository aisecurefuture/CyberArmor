<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;

final class XAI extends OpenAICompatible
{
    public function __construct(Client $client, object $openai, string $tenantId, string $model = 'grok-3')
    {
        parent::__construct($client, $openai, $tenantId, 'xai', $model);
    }
}

