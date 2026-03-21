<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;

final class Perplexity extends OpenAICompatible
{
    public function __construct(Client $client, object $openai, string $tenantId, string $model = 'sonar')
    {
        parent::__construct($client, $openai, $tenantId, 'perplexity', $model);
    }
}

