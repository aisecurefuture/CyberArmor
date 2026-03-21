<?php

declare(strict_types=1);

namespace CyberArmor\Providers;

use CyberArmor\Client;

final class Google extends OpenAICompatible
{
    public function __construct(Client $client, object $openai, string $tenantId, string $model = 'gemini-2.0-flash')
    {
        parent::__construct($client, $openai, $tenantId, 'google', $model);
    }
}

