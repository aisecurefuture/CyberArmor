<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;

final class Meta extends OpenAICompatible
{
    public function __construct(Client $client, object $openai, string $tenantId, string $model = 'llama-3.3-70b-instruct')
    {
        parent::__construct($client, $openai, $tenantId, 'meta', $model);
    }
}

