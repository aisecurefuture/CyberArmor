<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;

final class Microsoft extends OpenAICompatible
{
    public function __construct(Client $client, object $openai, string $tenantId, string $model = 'phi-4')
    {
        parent::__construct($client, $openai, $tenantId, 'microsoft', $model);
    }
}

