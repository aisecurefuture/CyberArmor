<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;

final class Amazon extends OpenAICompatible
{
    public function __construct(Client $client, object $openai, string $tenantId, string $model = 'amazon.nova-lite-v1:0')
    {
        parent::__construct($client, $openai, $tenantId, 'amazon', $model);
    }
}

