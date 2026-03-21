<?php

declare(strict_types=1);

namespace CyberArmor\Tests\Providers;

use CyberArmor\Client;
use CyberArmor\Providers\OpenAICompatible;
use PHPUnit\Framework\TestCase;

final class OpenAICompatibleTest extends TestCase
{
    private static $serverProcess = null;
    private static string $tmpDir;
    private static int $port;

    public static function setUpBeforeClass(): void
    {
        self::$tmpDir = sys_get_temp_dir() . '/cyberarmor-php-test-' . bin2hex(random_bytes(4));
        mkdir(self::$tmpDir, 0777, true);
        self::$port = random_int(20000, 40000);

        $router = <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$body = file_get_contents('php://input') ?: '{}';

if (preg_match('#^/policies/[^/]+/evaluate$#', $uri)) {
    file_put_contents(__DIR__ . '/evaluate.json', $body);
    header('Content-Type: application/json');
    echo json_encode([
        'allowed' => true,
        'decision_type' => 'ALLOW_WITH_REDACTION',
        'reason' => 'redacted',
        'redacted_prompt' => '[REDACTED]',
    ]);
    exit;
}

if ($uri === '/audit/events') {
    file_put_contents(__DIR__ . '/audit.json', $body);
    header('Content-Type: application/json');
    echo json_encode(['ok' => true]);
    exit;
}

http_response_code(404);
echo 'not found';
PHP;
        file_put_contents(self::$tmpDir . '/router.php', $router);

        $cmd = sprintf('php -S 127.0.0.1:%d router.php', self::$port);
        self::$serverProcess = proc_open(
            $cmd,
            [
                0 => ['pipe', 'r'],
                1 => ['file', self::$tmpDir . '/server.out.log', 'a'],
                2 => ['file', self::$tmpDir . '/server.err.log', 'a'],
            ],
            $pipes,
            self::$tmpDir
        );

        usleep(300000);
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$serverProcess)) {
            proc_terminate(self::$serverProcess);
        }
    }

    public function testChatRoutesProviderAppliesRedactionAndEmitsAudit(): void
    {
        $client = new Client(
            url: 'http://127.0.0.1:' . self::$port,
            agentId: 'agent-1',
            agentSecret: 'secret-1',
            enforceMode: 'enforce',
            failOpen: false,
            auditUrl: 'http://127.0.0.1:' . self::$port
        );

        $openai = new class {
            public array $captured = [];

            public function chat(): self
            {
                return $this;
            }

            public function create(array $params): array
            {
                $this->captured = $params;
                return ['id' => 'resp_123'];
            }
        };

        $provider = new OpenAICompatible($client, $openai, 'tenant-1', 'google', 'gemini-2.0-flash');
        $result = $provider->chat([
            ['role' => 'system', 'content' => 'You are helpful'],
            ['role' => 'user', 'content' => 'My SSN is 123-45-6789'],
        ]);

        self::assertSame('resp_123', $result['id']);
        self::assertSame('[REDACTED]', $openai->captured['messages'][1]['content']);

        $evaluate = json_decode((string) file_get_contents(self::$tmpDir . '/evaluate.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('google', $evaluate['provider']);
        self::assertSame('gemini-2.0-flash', $evaluate['model']);

        $audit = json_decode((string) file_get_contents(self::$tmpDir . '/audit.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('completion_returned', $audit['event_type']);
        self::assertSame('google', $audit['payload']['provider']);
        self::assertSame('resp_123', $audit['payload']['response_id']);
    }
}
