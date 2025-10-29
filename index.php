<?php
# start
require_once './wire/start.php';
# request strings
$requestUri = trim($_SERVER['REQUEST_URI'], '/');
$scriptName = $_SERVER['SCRIPT_NAME'];
$scriptPath = dirname($scriptName);

$relativeUri = ($scriptPath === '/')
    ? $requestUri
    : preg_replace('#^' . preg_quote($scriptPath, '#') . '/?#i', '', $requestUri);

$uriParts = $relativeUri === '' ? [] : explode('/', $relativeUri);

$method = $_SERVER['REQUEST_METHOD'];
$entity = $uriParts[0] ?? null;
$id = $uriParts[1] ?? null;
# router
try {
    if (empty($entity)) {
        View::render(['message' => 'wait for requests', 'details' => 'Frontity API Prototype 2, by d0lmany']);
    } else {
        require_once './controller.php';
        $controller = new Controller($pdo, $entity, $kernel);
        switch ($method) {
            case 'GET':
                if (!empty($id)) {
                    if (!is_int((int)$id)) {
                        $response = ['error' => 'incorrect type', 'reason' => 'Expected \'int\''];
                        break;
                    }
                    $response = $controller->getById($id);
                } else {
                    $response = $controller->getAll();
                }
                break;
            case 'POST':
                $request = json_decode(file_get_contents('php://input'), true) ?? [];
                if (!is_array($request)) {
                    $response = ['error' => 'incorrect type', 'reason' => 'Expected \'JSON\''];
                    break;
                }
                switch ($entity) {
                    case '@serviceToken':
                        $response = $controller->serviceToken($request);
                        break;
                    case '@auth':
                        $response = $controller->auth($request['token'] ?? '');
                        break;
                    default:
                        if (array_key_exists($entity, $kernel['filepaths'])) {
                            $controller->initFU();
                            $response = $controller->postFiles();
                        } else {
                            if ($id === '@options') {
                                $response = $controller->getAll($request);
                            } else {
                                $response = $controller->post($request);
                            }
                        }
                }
                break;
            case 'DELETE':
                if (!empty($id)) {
                    if (array_key_exists($entity, $kernel['filepaths']) && is_string($id)) {
                        $controller->initFU();
                        $response = $controller->deleteFiles($id);
                    } elseif (is_int((int)$id)) {
                        $response = $controller->delete($id);
                    } else {
                        $response = ['error' => 'incorrect type', 'reason' => 'Expected \'int|string\''];
                    }
                } else {
                    $response = ['error' => 'object is not selected'];
                }
                break;
            case 'PUT':
                if (!empty($id)) {
                    if (!is_int((int)$id)) {
                        $response = ['error' => 'Need ID'];
                        break;
                    }
                    $request = json_decode(file_get_contents('php://input'), true) ?? [];
                    if (!is_array($request)) {
                        $response = ['error' => 'incorrect type', 'reason' => 'Expected \'JSON\''];
                        break;
                    }
                    $response = $controller->put($id, $request);
                } else {
                    $response = ['error' => 'object is not selected'];
                }
                break;
            case 'PATCH':
                if (!empty($id)) {
                    if (!is_int((int)$id)) {
                        $response = ['error' => 'Need ID'];
                        break;
                    }
                    $request = json_decode(file_get_contents('php://input'), true) ?? [];
                    if (!is_array($request)) {
                        $response = ['error' => 'incorrect type'];
                        break;
                    }
                    $response = $controller->patch((int)$id, $request);
                } else {
                    $response = ['error' => 'object is not selected'];
                }
                break;
            case 'OPTIONS':
                header('HTTP/1.1 204 No Content');
                foreach ($kernel['headers'] as $header) {
                    header($header);
                }
                exit;
            default:
                $response = ['error' => 'method is not allowed'];
        }
        View::render($response, $kernel['headers']);
    }
} catch (Exception $e) {
    http_response_code(503);
    $errmsg = $e->getMessage();
    echo json_encode(['error' => 'unavailable...', 'reason' => $errmsg]);
    error_log(date('Y-m-d H:i:s')." | ".$errmsg);
}
# logging
if ($kernel['rules']['logging'] ?? true) {
    $logFile = $kernel['rules']['logging_file'] ?? 'log.log';

    try {
        $logDir = dirname($logFile);
        if (!is_dir($logDir) && !mkdir($logDir, 0755, true) && !is_dir($logDir)) {
            throw new RuntimeException("log directory creation failed: $logDir");
        }

        $logData = [
            $method,
            date('Y-m-d H:i:s'),
            htmlspecialchars($_SERVER['REQUEST_URI'] ?? '', ENT_QUOTES),
            $_SERVER['REMOTE_ADDR'] ?? '',
            htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? '', ENT_QUOTES),
            htmlspecialchars($errmsg ?? 'no errors', ENT_QUOTES)
        ];
        $logLine = implode(' | ', $logData) . PHP_EOL;

        if ($handle = fopen($logFile, 'a')) {
            if (flock($handle, LOCK_EX)) {
                fwrite($handle, $logLine);
                flock($handle, LOCK_UN);
            }
            fclose($handle);
        }
    } catch (Exception $e) {
        error_log('logging failed: ' . $e->getMessage());
    }
}
# close
if (isset($controller)) {
    $controller->close();
    $controller = null;
}
$pdo = $kernel = $request = $response = null;