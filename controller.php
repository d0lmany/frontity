<?php
require_once './wire/model.php';
require_once './wire/FileUploader.php';

class Controller
{
    private ?Model $model;
    private ?string $entity;
    private ?array $validations;
    private ?array $hash;
    private ?array $roles;
    private ?array $rules;
    private ?array $forbiddenCORS;
    private ?string $owner_field;
    private ?array $filepath;
    private ?FileUploader $fu;

    public function __construct(PDO $pdo, string $entity, array $kernel)
    {
        $this->rules = $kernel['rules'] ?? [];
        $entity = $entity == '@serviceToken' ? $this->rules['user_entity_fields']['entity'] : $entity;
        $this->model = new Model($pdo, $entity, $kernel);
        $this->entity = $entity;
        $this->validations = $kernel['entities'][$entity]['validations'] ?? [];
        $this->hash = $kernel['entities'][$entity]['hash'] ?? [];
        $this->roles = $kernel['roles'] ?? [];
        $this->forbiddenCORS = $kernel['forbidden_cors'] ?? [];
        $this->owner_field = $kernel['entities'][$entity]['owner_field'] ?? '';
        $this->filepath = $kernel['filepaths'][$entity] ?? [];
    }

    public function getById(int $id): array
    {
        if ($id <= 0) {
            return ['error' => 'not found'];
        }
        return $this->handleRequest('getById', fn() => $this->model->getById($id));
    }

    public function getAll(array $options = []): array
    {
        return $this->handleRequest('getAll', fn() => $this->model->getAll($options));
    }

    public function post(array $data): array
    {
        if (empty($data)) {
            return ['error' => 'no data'];
        }
        return $this->handleRequest('post', fn() => $this->model->post($data), $this->itIsNeedValidate(), $data);
    }

    public function put(int $id, array $data): array
    {
        if ($id <= 0) {
            return ['error' => 'not found'];
        }
        if (empty($data)) {
            return ['error' => 'no data'];
        }
        return $this->handleRequest('put', fn() => $this->model->put($id, $data), $this->itIsNeedValidate(), $data, $id);
    }

    public function patch(int $id, array $data): array
    {
        if ($id <= 0) {
            return ['error' => 'not found'];
        }
        if (empty($data)) {
            return ['error' => 'no data'];
        }
        return $this->handleRequest('patch', fn() => $this->model->patch($id, $data), $this->itIsNeedValidate(), $data, $id);
    }

    public function delete(int $id): array
    {
        if ($id <= 0) {
            return ['error' => 'not found'];
        }
        return $this->handleRequest('delete', fn() => $this->model->delete($id), false, [], $id);
    }

    public function serviceToken(array $data): array
    {
        if (empty($data)) {
            return ['error' => 'no data'];
        }
        return $this->handleRequest('serviceToken', fn() => $this->model->serviceToken(
            $data,
            $this->rules['user_entity_fields'],
            $this->hash
        ));
    }

    public function auth(string $token): array
    {
        if (empty($token)) {
            return ['error' => 'no data'];
        }
        return $this->handleRequest('auth', fn() => $this->model->auth($this->rules['user_entity_fields'], $token));
    }

    public function initFU(): void
    {
        $this->fu = new FileUploader($this->entity, $this->filepath);
    }

    public function postFiles(): array
    {
        return $this->handleRequest('postFiles', fn() => $this->fu->post());
    }

    public function deleteFiles(string $filename): array
    {
        return $this->handleRequest('deleteFiles', fn() => $this->fu->delete($filename));
    }

    private function handleRequest(string $method, callable $function, bool $needValidate = false, array $data = [], int $recordId = 0): array
    {
        $permission = $this->checkPermission($method);
        if ($permission !== true) {
            return $permission;
        }

        if ($this->isForbidden($method)) {
            return ['error' => 'forbidden', 'reason' => 'method `' . $method . '` forbidden for this entity'];
        }

        $methods = ['put', 'patch', 'delete'];
        if (in_array($method, $methods, true) && !empty($this->owner_field)) {
            if (!$this->isOwner($recordId)) {
                return ['error' => 'forbidden', 'reason' => 'user is not owner'];
            }
        }

        if ($needValidate) {
            $validate = $this->validate($data);
            if ($validate !== true) {
                return $validate;
            }
        }

        try {
            $response = $function();
        } catch (Exception $e) {
            $response = ['error' => 'model fail', 'reason' => $e->getMessage()];
        }

        return empty($response)
            ? ['error' => 'not found']
            : $this->decryptIfNeed($response);
    }

    private function isOwner(int $recordId): bool
    {
        if ($this->rules['ignore_ownership'] ?? false) {
            return true;
        }

        if (empty($this->owner_field)) {
            return true;
        }

        $user = $this->auth($this->getTokenFromHeader());
        if (isset($user['error'])) {
            return false;
        }

        try {
            $ownerId = $this->model->getOwnerId($recordId, $this->owner_field);
            return $ownerId !== null && $user['id'] == $ownerId;
        } catch (Exception) {
            return false;
        }
    }

    private function itIsNeedValidate(): bool
    {
        return !($this->rules['ignore_validations'] ?? false);
    }

    private function validate(array &$data): array|true
    {
        $errors = [];

        foreach ($this->validations as $field => $rules) {
            $value = $data[$field] ?? null;

            if (!empty($rules['required']) && !array_key_exists($field, $data)) {
                $errors[$field][] = 'field is required';
                continue;
            }

            if ($value === null) {
                continue;
            }

            if (isset($rules['type'])) {
                $typeValid = match ($rules['type']) {
                    'string' => is_string($value),
                    'int' => filter_var($value, FILTER_VALIDATE_INT),
                    'float' => filter_var($value, FILTER_VALIDATE_FLOAT),
                    'double' => is_double($value),
                    'bool' => is_bool($value),
                    'array' => is_array($value),
                    default => false
                };

                if (!$typeValid) {
                    $errors[$field][] = 'field must be of type ' . $rules['type'];
                }
            }

            if (isset($rules['regex'])) {
                if (is_int($rules['regex'])) {
                    if (!filter_var($value, $rules['regex'])) {
                        $errors[$field][] = 'invalid format';
                    }
                } elseif ($rules['regex'] === 'htmlspecialchars') {
                    $data[$field] = htmlspecialchars($data[$field], ENT_QUOTES);
                } else {
                    if (!preg_match($rules['regex'], $value)) {
                        $errors[$field][] = 'value does not match required pattern';
                    }
                }
            }

            if (isset($rules['min']) && is_numeric($value) && $value < $rules['min']) {
                $errors[$field][] = 'value must be least ' . $rules['min'];
            }

            if (isset($rules['max']) && is_numeric($value) && $value > $rules['max']) {
                $errors[$field][] = 'value must be no more than ' . $rules['max'];
            }
        }
        return empty($errors) ? true : ['error' => $errors];
    }

    private function decryptIfNeed(array $data): array
    {
        if (!($this->rules['decrypt_for_request'] ?? true)) {
            return $data;
        }

        static $decryptMap = null;
        if ($decryptMap === null) {
            $decryptMap = [];
            foreach ($this->hash as $hashRow) {
                if ($hashRow['method'] === 'openssl') {
                    $decryptMap[$hashRow['field']] = $hashRow['attribute'];
                }
            }
        }

        $isArrayOfObjects = !empty($data) && is_array(reset($data));

        if ($isArrayOfObjects) {
            foreach ($data as &$item) {
                foreach ($decryptMap as $field => $algorithm) {
                    if (isset($item[$field])) {
                        try {
                            $item[$field] = $this->model->opensslDecrypt($item[$field], $algorithm);
                        } catch (Exception $e) {
                            error_log("Decryption failed for field {$field}: " . $e->getMessage());
                            $item[$field] = null;
                        }
                    }
                }
            }
            unset($item);
        } else {
            foreach ($decryptMap as $field => $algorithm) {
                if (isset($data[$field])) {
                    try {
                        $data[$field] = $this->model->opensslDecrypt($data[$field], $algorithm);
                    } catch (Exception $e) {
                        error_log("Decryption failed for field {$field}: " . $e->getMessage());
                        $data[$field] = null;
                    }
                }
            }
        }

        return $data;
    }

    private function isForbidden(string $method): bool
    {
        if (empty($this->forbiddenCORS)) {
            return false;
        }

        $forbiddenMethods = $this->forbiddenCORS[$this->entity] ?? null;

        return $forbiddenMethods !== null
            && (in_array('*', $forbiddenMethods, true)
                || in_array($method, $forbiddenMethods, true));
    }

    private function checkPermission(string $method): array|bool
    {
        if ($this->rules['ignore_roles'] ?? false) {
            return true;
        }

        if ($method == 'auth' || $method == 'serviceToken') {
            return true;
        }

        $token = $this->getTokenFromHeader();
        if (empty($token)) return ['error' => 'unauthorized', 'reason' => 'token required'];

        $user = $this->model->auth($this->rules['user_entity_fields'], $token);
        if (isset($user['error'])) {
            return $user;
        }

        if (empty($this->roles)) {
            return true;
        }

        $userRole = $user['role'] ?? null;
        $entityRules = $this->roles[$userRole][$this->entity] ?? null;
        if (!empty($this->filepath)) {
            return true;
        }
        if ($entityRules === null) {
            return ['error' => 'forbidden', 'reason' => 'role has no permissions for this entity: ' . $this->entity];
        }
        if (in_array('*', $entityRules) || in_array($method, $entityRules)) {
            return true;
        }

        return ['error' => 'forbidden', 'reason' => 'method not allowed for this role'];
    }

    private function getTokenFromHeader(): string
    {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $header = $_SERVER['HTTP_AUTHORIZATION'];
            if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                return $matches[1];
            }
        }
        return '';
    }

    public function close(): void
    {
        if ($this->model !== null) {
            $this->model->close();
        }
        $this->model = null;
        if (!empty($this->fu)) {
            $this->fu->close();
            $this->fu = null;
        }
        $this->fu = null;
        $this->validations = null;
        $this->hash = null;
        $this->roles = null;
        $this->rules = null;
        $this->forbiddenCORS = null;
        $this->owner_field = null;
        $this->filepath = null;
    }
}
