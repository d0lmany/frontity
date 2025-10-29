<?php
class View
{
    private const OK = 200;
    private const CREATED = 201;

    private const BAD_REQUEST = 400;
    private const UNAUTHORIZED = 401;
    private const FORBIDDEN = 403;
    private const NOT_FOUND = 404;
    private const METHOD_NOT_ALLOWED = 405;
    private const GONE = 410;
    private const UNPROCESSABLE_ENTITY = 422;

    private const INTERNAL_SERVER_ERROR = 500;
    private const NOT_IMPLEMENTED = 501;
    private const SERVICE_UNAVAILABLE = 503;

    public static function render(array $data, array $headers = ['Content-Type: application/json; charset=utf-8']): void
    {
        try {
            # headers
            foreach ($headers as $header) {
                header($header);
            }
            # creating code
            $code = 200;
            switch (array_key_first($data)) {
                case 'message':
                    $code = self::handleSuccess($data['message']);
                    break;
                case 'error':
                    $code = self::handleError($data['error']);
                    if (is_array($data['error'])) {
                        $data = ['error' => $data['error']];
                    }
                    error_log(date('Y-m-d H:i:s')." | ".$data['error']);
                    break;
            }
        } catch (Exception $e) {
            http_response_code(self::INTERNAL_SERVER_ERROR);
            echo json_encode(['error' => 'can\'t render', 'reason' => $e->getMessage(), 'raw' => $data]);
            error_log(date('Y-m-d H:i:s')." | ".$e->getMessage());
        }
        # render
        http_response_code($code);
        echo json_encode($data);
    }

    private static function handleSuccess(string $condition): int
    {
        $conditionMap = [
            'was added' => self::CREATED,
            'was updated' => self::CREATED,
            'token generated' => self::CREATED,
            'File was saved' => self::CREATED,
        ];
        return $conditionMap[$condition] ?? self::OK;
    }

    private static function handleError(string|array $error): int
    {
        if (is_array($error)) {
            return self::UNPROCESSABLE_ENTITY;
        }
        $errorMap = [
            'server is temporarily unavailable' => self::SERVICE_UNAVAILABLE,
            'insufficient or incorrect data' => self::UNPROCESSABLE_ENTITY,
            'incorrect password' => self::UNAUTHORIZED,
            'update failed' => self::BAD_REQUEST,
            'empty credentials' => self::BAD_REQUEST,
            'user not found' => self::NOT_FOUND,
            'openSSL key missing' => self::NOT_FOUND,
            'forbidden' => self::FORBIDDEN,
            'unauthorized' => self::UNAUTHORIZED,
            'not found' => self::NOT_FOUND,
            'no data' => self::BAD_REQUEST,
            'server is gone' => self::GONE,
            'object is not selected' => self::BAD_REQUEST,
            'method is not allowed' => self::METHOD_NOT_ALLOWED,
            'incorrect type' => self::BAD_REQUEST,
            'Need ID' => self::BAD_REQUEST,

            'FileUploader not configured' => self::NOT_IMPLEMENTED,
            'File upload error' => self::INTERNAL_SERVER_ERROR,
            'File failed validation' => self::BAD_REQUEST,
        ];
        return $errorMap[$error] ?? self::INTERNAL_SERVER_ERROR;
    }
}
