<?php
class FileUploader
{
    private ?array $config;
    private ?string $section;
    private ?string $type;
    private ?string $path;

    public function __construct(string $section, array $config)
    {
        $this->config = $config ?? [];
        $this->section = $section ?? 'file';
        $this->path = ($_SERVER['DOCUMENT_ROOT'] . '/' . ltrim($config['path'], '/')) ?? '';
    }

    public function post(): array
    {
        # config
        if (empty($this->config) || empty($this->path)) {
            return ['error' => 'FileUploader not configured'];
        }
        $overwrite = $this->config['overwrite'] ?? true;
        # file
        ## get him
        if (!isset($_FILES[$this->section])) {
            return ['error' => 'no data'];
        }
        $file = $_FILES[$this->section];
        ## upload error
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return ['error' => 'File upload error', 'reason' => $file['error']];
        }
        ## validate
        $stmt = $this->validate($file);
        if (!empty($stmt)) {
            return ['error' => 'File failed validation', 'reason' => $stmt];
        }
        $filename = $this->prepare(pathinfo($file['name'], PATHINFO_FILENAME));
        $fileext = $this->prepare(pathinfo($file['name'], PATHINFO_EXTENSION));
        ## path
        $newName = $filename.'.'.$fileext;
        $filepath = $this->path.'/'.$newName;
        if (!is_dir($this->path)) {
            if (!mkdir($this->path, 0755)) {
                return ['error' => 'Path creation error'];
            }
        }
        ## save
        if (!$overwrite) {
            while (file_exists($filepath)) {
                $newName = bin2hex(random_bytes(16)).'.'.$fileext;
                $filepath = $this->path.'/'.$newName;
            }
        }
        ## response
        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            return [
                'message' => 'File was saved',
                'filename' => $newName,
                'url' => ltrim(str_replace($_SERVER['DOCUMENT_ROOT'], '', $filepath)),
                'size' => $file['size'],
                'mime_type' => $this->type,
            ];
        }
        return ['error' => 'File error saved'];
    }

    public function delete(string $filename): array
    {
        $filename = $this->path.'/'.basename($filename);

        if (!file_exists($filename)) {
            return ['error' => 'not found'];
        }

        if (!unlink($filename)) {
            return ['error' => 'File deletion error'];
        }

        return ['message' => 'was deleted'];
    }

    private function prepare(string $string): string
    {
        $newString = preg_replace('/[^\p{L}\p{N}_-]/u', '', $string);
        $newString = trim($newString);
        return $newString !== '' ? $newString : bin2hex(random_bytes(16));
    }

    private function validate(array $file): string
    {
        # type
        $mimeTypes = $this->config['mimeTypes'] ?? ['*'];
        if (!in_array($file['type'], $mimeTypes) && !in_array('*', $mimeTypes)) {
            return $file['type'].' is not allowed filetype';
        }
        # minSize
        if ($this->config['min_size'] !== null && $file['size'] < $this->config['min_size']) {
            return 'file is too small';
        }
        # maxSize
        if ($this->config['max_size'] !== null && $file['size'] > $this->config['max_size']) {
            return 'file is too large';
        }
        # ok
        $this->type = $file['type'];
        return '';
    }

    public function close(): void
    {
        $this->config = null;
        $this->section = null;
        $this->type = null;
        $this->path = null;
    }
}