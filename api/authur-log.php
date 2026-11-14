<?php
/**
 * Public activity log for authur.ai.
 *
 * GET  /api/authur-log.php   redacted JSON array (also used for /api/authur-log)
 * POST /api/authur-log.php   append one entry; requires X-Authur-Token
 * OPTIONS                    CORS preflight
 *
 * The write token is read from the AUTHUR_LOG_TOKEN environment variable, or from
 * api/.authur-token (one line, not committed). This file does not contain a secret.
 */

declare(strict_types=1);

function authur_redact_text(string $text): string
{
    $text = (string) preg_replace(
        '/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i',
        '[redacted-email]',
        $text
    );
    $text = (string) preg_replace(
        '/(?<!\d)(?:\+?1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}(?!\d)/',
        '[redacted-phone]',
        $text
    );
    $text = (string) preg_replace_callback(
        '/\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ai|co|us|info|biz|cc|me|app|dev|xyz|online|site|shop|cloud|email|tech|pro|tv|uk|ca|de|nl|eu|gov|edu)\b/i',
        static function (array $match): string {
            $domain = strtolower($match[0]);
            if (in_array($domain, ['authur.ai', 'www.authur.ai', 'advyon.com', 'www.advyon.com'], true)) {
                return $match[0];
            }
            return '[redacted-domain]';
        },
        $text
    );
    $text = (string) preg_replace(
        '/(^|[^A-Za-z0-9._%+\-])@([A-Za-z][A-Za-z0-9_]{2,})/',
        '$1@[redacted]',
        $text
    );

    return $text;
}

function authur_redact_entry(array $item): array
{
    $type = isset($item['type']) ? (string) $item['type'] : 'done';
    if (!in_array($type, ['done', 'note', 'task'], true)) {
        $type = 'done';
    }

    return [
        'time' => authur_clip(isset($item['time']) ? (string) $item['time'] : '', 32),
        'type' => $type,
        'body' => authur_redact_text(authur_clip(isset($item['body']) ? (string) $item['body'] : '', 600)),
        'meta' => authur_redact_text(authur_clip(isset($item['meta']) ? (string) $item['meta'] : '', 160)),
    ];
}

function authur_clip(string $value, int $max): string
{
    $value = trim(str_replace(["\r", "\n"], ' ', $value));
    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, $max);
    }
    return substr($value, 0, $max);
}

function authur_log_path(): string
{
    return dirname(__DIR__) . '/live_log.json';
}

/**
 * @return array{ok:bool,entries:array,error:string}
 */
function authur_read_log(string $path): array
{
    if (!is_file($path)) {
        return ['ok' => true, 'entries' => [], 'error' => ''];
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        return ['ok' => false, 'entries' => [], 'error' => 'Log unavailable'];
    }
    if (trim($raw) === '') {
        return ['ok' => true, 'entries' => [], 'error' => ''];
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return ['ok' => false, 'entries' => [], 'error' => 'Log unavailable'];
    }

    $entries = [];
    foreach ($data as $item) {
        if (is_array($item)) {
            $entries[] = authur_redact_entry($item);
        }
    }
    return ['ok' => true, 'entries' => $entries, 'error' => ''];
}

function authur_expected_token(): string
{
    $env = getenv('AUTHUR_LOG_TOKEN');
    if (is_string($env) && trim($env) !== '') {
        return trim($env);
    }
    $file = __DIR__ . '/.authur-token';
    if (is_file($file)) {
        $token = trim((string) file_get_contents($file));
        if ($token !== '') {
            return $token;
        }
    }
    return '';
}

function authur_send(int $status, $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-Authur-Token');
    if ($payload !== null) {
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

function authur_serve(): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($method === 'OPTIONS') {
        authur_send(204, null);
        return;
    }

    $path = authur_log_path();

    if ($method === 'GET') {
        $log = authur_read_log($path);
        if (!$log['ok']) {
            authur_send(500, ['ok' => false, 'error' => 'Log unavailable']);
            return;
        }
        authur_send(200, $log['entries']);
        return;
    }

    if ($method !== 'POST') {
        authur_send(405, ['ok' => false, 'error' => 'Method not allowed']);
        return;
    }

    $expected = authur_expected_token();
    $given = $_SERVER['HTTP_X_AUTHUR_TOKEN'] ?? '';
    if ($expected === '' || !is_string($given) || !hash_equals($expected, $given)) {
        authur_send(403, ['ok' => false, 'error' => 'Not authorized']);
        return;
    }

    $raw = file_get_contents('php://input');
    $item = json_decode($raw === false ? '' : $raw, true);
    if (!is_array($item) || trim((string) ($item['body'] ?? '')) === '') {
        authur_send(400, ['ok' => false, 'error' => 'Expected a JSON entry with a body']);
        return;
    }
    if (!isset($item['time']) || trim((string) $item['time']) === '') {
        $item['time'] = date('h:i A');
    }

    $entry = authur_redact_entry($item);
    $handle = fopen($path, 'c+');
    if ($handle === false) {
        authur_send(500, ['ok' => false, 'error' => 'Log unavailable']);
        return;
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            authur_send(500, ['ok' => false, 'error' => 'Log unavailable']);
            return;
        }
        $log = authur_read_log($path);
        if (!$log['ok']) {
            authur_send(500, ['ok' => false, 'error' => 'Log unavailable']);
            return;
        }
        $entries = $log['entries'];
        $entries[] = $entry;
        if (count($entries) > 200) {
            $entries = array_slice($entries, -200);
        }
        rewind($handle);
        $json = json_encode(
            $entries,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        if ($json === false || fwrite($handle, $json . "\n") === false) {
            authur_send(500, ['ok' => false, 'error' => 'Log unavailable']);
            return;
        }
        ftruncate($handle, ftell($handle));
        fflush($handle);
        flock($handle, LOCK_UN);
    } finally {
        fclose($handle);
    }

    authur_send(200, ['ok' => true]);
}

if (PHP_SAPI !== 'cli') {
    $script = realpath($_SERVER['SCRIPT_FILENAME'] ?? '');
    $uri = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '';
    $direct = $script !== false && $script === realpath(__FILE__);
    $routed = (bool) preg_match('#/authur-log(?:\.php)?$#', $uri);
    if ($direct || $routed) {
        authur_serve();
    }
}
