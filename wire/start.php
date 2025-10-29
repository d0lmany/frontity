<?php
# including
$kernel = require_once './wire/config.php';
require_once './view.php';
# is ok
if (!empty($kernel['gone'])) {
    View::render(['error' => 'server is gone']);
    exit;
}
if (!empty($kernel['maintenance'])) {
    View::render(['error' => 'server is temporarily unavailable']);
    exit;
}
# env
try {
    $envFile = $_SERVER['DOCUMENT_ROOT'] . '/.env';
    if (!is_file($envFile)) {
        throw new Exception('.env file not found');
    }
    $env = parse_ini_file($envFile);
    if ($env === false) {
        throw new Exception('failed to parse .env');
    }
    $_ENV = array_merge($_ENV, $env);
    $requiredVars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_CHARSET', 'APP_MODE'];
    foreach ($requiredVars as $var) {
        if (!isset($_ENV[$var])) {
            throw new Exception("missing required env variable: $var");
        }
    }
    $appMode = $_ENV['APP_MODE'];
    if (!isset($kernel[$appMode])) {
        throw new Exception("undefined mode: $appMode");
    }
    $kernel = $kernel[$appMode];
} catch (Exception $e) {
    View::render([
        'error' => 'could not load environment',
        'reason' => $e->getMessage()
    ]);
    exit;
}
# db connection
try {
    $db = $kernel['database'] ?? 'mysql';
    $dsn = "{$db}:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']};charset={$_ENV['DB_CHARSET']}";
    $pdo = new PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASSWORD']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    View::render([
        'error' => 'can\'t connect to the database',
        'reason' => $e->getMessage()
    ]);
    exit;
}