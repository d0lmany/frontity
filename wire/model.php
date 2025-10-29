<?php
class Model
{
    private ?PDO $pdo;
    private ?string $entity;
    private ?array $entitySettings;

    public function __construct(PDO $pdo, string $entity, array $kernel)
    {
        $this->pdo = $pdo;
        $this->entity = $entity;
        $this->entitySettings = $kernel['entities'][$entity] ?? [];
    }

    public function getById(int $id): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM `{$this->entity}` WHERE id = :id");
        try {
            $stmt->execute(['id' => $id]);
            $response = $stmt->fetch(PDO::FETCH_ASSOC);
            if (is_array($response))
                return $this->hideFields($response);
            else
                return ['error' => 'not found'];
        } catch (Exception $e) {
            if ($e instanceof PDOException) {
                return ["error" => $e->errorInfo];
            }
            return ["error" => "unexpected error occurred", 'reason' => $e->getMessage()];
        }
    }

    public function getAll(array $options = []): array
    {
        $sql = "SELECT * FROM `{$this->entity}`";
        $params = [];
        $whereConditions = [];

        if (!empty($options['search'])) {
            if (empty($options['search']['fields']) || empty($options['search']['query'])) {
                return ['error' => 'insufficient or incorrect data', 'reason' => 'search requires both \'fields\' and \'query\' parameters'];
            }

            $searchConditions = [];
            foreach ($options['search']['fields'] as $i => $field) {
                $paramName = ":search_{$i}";
                $searchConditions[] = "{$field} LIKE {$paramName}";
                $params[$paramName] = "%{$options['search']['query']}%";
            }
            $whereConditions[] = "(" . implode(' OR ', $searchConditions) . ")";
        }

        if (!empty($options['filter'])) {   
            if (!is_array($options['filter'])) {
                return ['error' => 'insufficient or incorrect data', 'reason' => 'filter must be an associative array'];
            }

            $filterConditions = [];
            foreach ($options['filter'] as $field => $value) {
                if (is_array($value)) {
                    $placeholders = [];
                    foreach ($value as $i => $val) {
                        $paramName = ":filter_{$field}_{$i}";
                        $placeholders[] = $paramName;
                        $params[$paramName] = $val;
                    }
                    $filterConditions[] = "{$field} IN (" . implode(',', $placeholders) . ")";
                } else {
                    $paramName = ":filter_{$field}";
                    $filterConditions[] = "{$field} = {$paramName}";
                    $params[$paramName] = $value;
                }
            }
            $whereConditions[] = "(" . implode(' AND ', $filterConditions) . ")";
        }

        if (!empty($whereConditions)) {
            $sql .= " WHERE " . implode(' AND ', $whereConditions);
        }

        if (!empty($options['pagination'])) {
            if (!isset($options['pagination']['limit'])) {
                return ['error' => 'insufficient or incorrect data', 'reason' => 'pagination requires at least \'limit\' parameter'];
            }

            $sql .= " LIMIT :limit";
            $params[':limit'] = (int)$options['pagination']['limit'];

            if (isset($options['pagination']['offset'])) {
                $sql .= " OFFSET :offset";
                $params[':offset'] = (int)$options['pagination']['offset'];
            }
        }

        try {
            $stmt = $this->pdo->prepare($sql);

            foreach ($params as $key => $value) {
                $type = is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR;
                $stmt->bindValue($key, $value, $type);
            }

            $stmt->execute();
            return $this->hideFields($stmt->fetchAll(PDO::FETCH_ASSOC));
        } catch (Exception $e) {
            return ['error' => 'Database request error', 'reason' => $e->getMessage()];
        }
    }

    public function post(array $data): array
    {
        if (isset($this->entitySettings['hash'])) {
            $data = $this->hashFields($data, $this->entitySettings['hash'] ?? []);
        }
        if (isset($data['@msg@'])) {
            $msg = $data['@msg@'];
            unset($data['@msg@']);
        }
        try {
            $columns = implode('`,`', array_keys($data));
            $placeholders = implode(',', array_fill(0, count($data), '?'));
            $stmt = $this->pdo->prepare("INSERT INTO `{$this->entity}` (`{$columns}`) VALUES ({$placeholders})");
            $stmt->execute(array_values($data));
            $response = ['message' => 'was added', 'id' => $this->pdo->lastInsertId()];
            if (isset($msg)) $response['details'] = $msg;
            return $response;
        } catch (Exception $e) {
            return ['error' => 'Database request error', 'reason' => $e->getMessage()];
        }
    }

    public function put(int $id, array $data): array
    {
        return $this->updater($id, $data, true);
    }

    public function patch(int $id, array $data): array
    {
        return $this->updater($id, $data, false);
    }

    public function delete(int $id): array
    {
        try {
            if (!$this->isExist($id)) {
                throw new Exception('id not found');
            }
            $sql = "DELETE FROM `{$this->entity}` WHERE id = :id";
            $stmt = $this->pdo->prepare($sql);
            if (!$stmt) throw new Exception('prepare failed: ' . implode(', ', $this->pdo->errorInfo()));
            if (!$stmt->execute([':id' => $id])) throw new Exception('execute failed: ' . implode(', ', $stmt->errorInfo()));
            if ($stmt->rowCount() === 0) throw new Exception('no records were deleted');
            return ['message' => 'was deleted'];
        } catch (Exception $e) {
            return ['error' => 'delete failed', 'reason' => $e->getMessage()];
        }
    }

    public function serviceToken(array $data, array $userFields, array $hashConfig): array
    {
        $login = $data['login'] ?? '';
        $password = $data['password'] ?? '';

        if (empty($login) || empty($password)) {
            return ['error' => 'empty credentials'];
        }

        $requiredFields = ['login', 'password', 'entity', 'token'];
        foreach ($requiredFields as $field) {
            if (!isset($userFields[$field]) || !is_string($userFields[$field])) {
                return ['error' => 'invalid user fields configuration'];
            }
        }

        try {
            $sql = sprintf(
                "SELECT id, `%s`, `%s` FROM `%s` WHERE `%s` = :login",
                $this->sanitizeIdentifier($userFields['login']),
                $this->sanitizeIdentifier($userFields['password']),
                $this->sanitizeIdentifier($userFields['entity']),
                $this->sanitizeIdentifier($userFields['login'])
            );

            $stmt = $this->pdo->prepare($sql);
            try {
                $login = $this->verifyLogin($login, $userFields['login'], $hashConfig);
            } catch (Exception $e) {
                return ['error' => 'bad hash configured', 'reason' => $e->getMessage()];
            }
            $stmt->execute([':login' => $login]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            return ['error' => 'database error'];
        }

        if (!$user) {
            return ['error' => 'user not found'];
        }

        if (!$this->verifyPassword($password, $user[$userFields['password']], $hashConfig, $userFields['password'])) {
            return ['error' => 'incorrect password'];
        }

        try {
            return $this->generateToken($userFields['token'], $user['id'], $userFields['entity']);
        } catch (Exception $e) {
            return ['error' => 'token generation failed', 'reason' => $e->getMessage()];
        }
    }

    private function verifyLogin(string $login, string $loginField ,array $hash): string
    {
        foreach ($hash as $element) {
            if ($element['field'] === $loginField) {
                return $this->opensslDecrypt($login, $element['attribute'] ?? 'AES-256-CBC');
            }
        }
        return $login;
    }

    private function verifyPassword(string $input, string $stored, array $hashConfig, string $passwordField): bool
    {
        foreach ($hashConfig as $config) {
            if ($config['field'] !== $passwordField) {
                continue;
            }

            switch ($config['method'] ?? '') {
                case 'password_hash':
                    return password_verify($input, $stored);

                case 'openssl':
                    $encrypted = $this->opensslEncrypt(
                        $input,
                        $config['attribute'] ?? 'AES-256-CBC'
                    );
                    return hash_equals($encrypted, $stored);

                case 'hash':
                    $algorithm = $config['attribute'] ?? 'sha256';
                    return hash_equals(hash($algorithm, $input), $stored);

                default:
                    throw new RuntimeException('unsupported hash method');
            }
        }

        throw new RuntimeException('no matching hash configuration found');
    }

    private function sanitizeIdentifier(string $identifier): string
    {
        return preg_replace('/[^a-zA-Z0-9_]/', '', $identifier);
    }

    private function updater(int $id, array $data, bool $isFullUpdate): array
    {
        try {
            if (!$this->isExist($id)) {
                throw new Exception('id not found');
            }
            $data = $this->hashFields($data, $this->entitySettings['hash'] ?? []);
            if ($isFullUpdate) {
                $stmt = $this->pdo->query('DESCRIBE ' . $this->entity);
                $fieldsInfo = $stmt->fetchAll(PDO::FETCH_ASSOC);
                $fields = [];
                foreach ($fieldsInfo as $field) {
                    if ($field['Extra'] != 'auto_increment') {
                        $fields[] = $field['Field'];
                    }
                }
                $actualKeys = array_keys($data);
                sort($actualKeys);
                sort($fields);
                if ($actualKeys !== $fields) {
                    $missingKeys = array_diff($fields, $actualKeys);
                    $extraKeys = array_diff($actualKeys, $fields);
                    $errors = [];
                    if (!empty($missingKeys)) {
                        $errors[] = 'missing fields: ' . implode(', ', $missingKeys);
                    }
                    if (!empty($extraKeys)) {
                        $errors[] = 'unknown fields: ' . implode(', ', $extraKeys);
                    }
                    throw new Exception(implode('. ', $errors));
                }
            }
            $fields = [];
            $params = [':id' => $id];
            foreach ($data as $key => $value) {
                $fields[] = "`$key` = :$key";
                $params[":$key"] = $value;
            }
            $sql = "UPDATE `{$this->entity}` SET " . implode(', ', $fields) . " WHERE id = :id";
            $stmt = $this->pdo->prepare($sql);
            if (!$stmt) throw new Exception('prepare failed: ' . implode(', ', $this->pdo->errorInfo()));
            if (!$stmt->execute($params)) throw new Exception('execute failed: ' . implode(', ', $stmt->errorInfo()));
            return ['message' => 'was updated'];
        } catch (Exception $e) {
            return ['error' => 'update failed', 'reason' => $e->getMessage()];
        }
    }

    private function generateToken(string $tokenField, int $id, string $entity): array
    {
        try {
            $token = bin2hex(random_bytes(32));
            $stmt = $this->pdo->prepare("UPDATE $entity SET $tokenField = :token WHERE id = :id");
            $stmt->execute([':token' => $token, ':id' => $id]);
            return ['token' => $token];
        } catch (Exception $e) {
            return ['error' => 'failed generate token', 'reason' => $e->getMessage()];
        }
    }

    public function auth(array $userFields, string $token): array
    {
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM {$userFields['entity']} WHERE {$userFields['token']} = :token");
            $stmt->execute([':token' => $token]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                return ['id' => $user['id'], 'role' => $user[$userFields['role']]];
            } else {
                return ['error' => 'unauthorized'];
            }
        } catch (PDOException $e) {
            return ['error' => 'db error', 'reason' => $e->getMessage()];
        }
    }

    public function getOwnerId(int $id, string $owner_field): int
    {
        try {
            $stmt = $this->pdo->prepare("SELECT {$owner_field} FROM {$this->entity} WHERE id = :id");
            $stmt->execute([':id' => $id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                return $user[$owner_field];
            } else {
                throw new Exception();
            }
        } catch (Exception) {
            return 0;
        }
    }

    private function isExist(int $id): bool
    {
        try {
            $stmt = $this->pdo->prepare("SELECT 1 FROM `{$this->entity}` WHERE id = ?");
            $stmt->execute([$id]);
            return (bool)$stmt->fetchColumn();
        } catch (PDOException) {
            return false;
        }
    }

    private function hashFields(array $data, array $hashConfig): array
    {
        if (empty($hashConfig)) {
            return $data;
        }

        if (array_keys($data) === range(0, count($data) - 1)) {
            foreach ($data as &$item) {
                $item = $this->processHashFields($data, $hashConfig);
            }
            unset($item);
            return $data;
        }
        return $this->processHashFields($data, $hashConfig);
    }

    private function processHashFields(array $item, array $hashConfig): array
    {
        foreach ($hashConfig as $config) {
            $field = $config['field'] ?? null;
            $method = $config['method'] ?? null;
            $attribute = $config['attribute'] ?? null;

            if (empty($field) || empty($method) || !isset($item[$field]) || empty($item[$field])) {
                continue;
            }

            switch ($method) {
                case 'password_hash':
                    $item[$field] = password_hash($item[$field], $attribute ?? PASSWORD_DEFAULT);
                    break;
                case 'openssl':
                    $item[$field] = $this->opensslEncrypt($item[$field], $attribute ?? 'AES-256-CBC');
                    break;
                case 'hash':
                    $item[$field] = hash($attribute ?? 'sha256', $item[$field]);
                    break;
                default:
                    $item['@error@'] = $item['@error@'] ?? [];
                    $item['@error@'][] = 'Unsupported hash method: ' . $method;
            }
        }

        return $item;
    }

    public function opensslDecrypt(string $encryptedData, string $method = 'AES-256-CBC'): string
    {
        $key = hex2bin($_ENV['OPENSSL_ENCRYPTION_KEY']) ?? '';
        if (empty($key)) {
            throw new RuntimeException('openSSL key missing');
        }
        $data = base64_decode($encryptedData, true);
        if ($data === false) {
            throw new RuntimeException("Base64 decoding failed");
        }
        $ivLength = openssl_cipher_iv_length($method);

        if (strlen($data) < $ivLength) {
            throw new RuntimeException('insufficient data for IV extraction');
        }

        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);

        if (strlen($iv) !== $ivLength) {
            throw new RuntimeException(sprintf(
                'IV length mismatch: expected %d bytes, got %d',
                $ivLength,
                strlen($iv)
            ));
        }

        $decrypted = openssl_decrypt(
            $encrypted,
            $method,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($decrypted === false) {
            throw new RuntimeException('openSSL decryption failed: ' . openssl_error_string());
        }

        return $decrypted;
    }

    private function opensslEncrypt(string $data, string $method): string
    {
        $key = hex2bin($_ENV['OPENSSL_ENCRYPTION_KEY']) ?? '';
        if (empty($key)) {
            throw new RuntimeException('openSSL key missing');
        }

        $ivLength = openssl_cipher_iv_length($method);
        $iv = openssl_random_pseudo_bytes($ivLength);

        if (strlen($iv) !== $ivLength) {
            throw new RuntimeException('failed to generate proper IV');
        }

        $encrypted = openssl_encrypt(
            $data,
            $method,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($encrypted === false) {
            throw new RuntimeException('openSSL encryption failed: ' . openssl_error_string());
        }
        return base64_encode($iv . $encrypted);
    }

    private function hideFields(array $data): array
    {
        $hiddenFields = $this->entitySettings['hidden_fields'] ?? [];
        if (empty($hiddenFields)) {
            return $data;
        }

        if (array_keys($data) === range(0, count($data) - 1)) {
            foreach ($data as &$item) {
                foreach ($hiddenFields as $field) {
                    unset($item[$field]);
                }
            }
            unset($item);
        } else {
            foreach ($hiddenFields as $field) {
                unset($data[$field]);
            }
        }
        return $data;
    }

    public function close(): void
    {
        $this->pdo = null;
        $this->entity = null;
        $this->entitySettings = null;
    }
}
