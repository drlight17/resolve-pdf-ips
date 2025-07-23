#!/usr/bin/env php
<?php

// === Настройки ===
$outputFile = 'output_ips.txt';
$logFile = 'resolve_log.txt';
$defaultListName = 'fstek_ban';
$langDir = 'lang';

// === Определение языка ===
function detectLocale($argv) {
    foreach ($argv as $arg) {
        if (preg_match('/^--locale=(en|ru)$/', $arg, $matches)) {
            return $matches[1];
        }
    }
    $locale = getenv('LC_ALL') ?: getenv('LANG');
    if ($locale && strpos($locale, 'ru') === 0) {
        return 'ru';
    }
    return 'en';
}

$locale = detectLocale($argv);
$langFile = "$langDir/$locale.json";
if (!file_exists($langFile)) {
    $langFile = "$langDir/en.json";
}
$LANG = json_decode(file_get_contents($langFile), true);
if (!$LANG) {
    die("Error loading language file: $langFile\n");
}

function __($key, ...$args) {
    global $LANG;
    $msg = $LANG[$key] ?? $key;
    return $args ? vsprintf($msg, $args) : $msg;
}

// === Вспомогательные функции ===

function ipInCIDR($ip, $cidr) {
    list($subnet, $bits) = explode('/', $cidr);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    return ($ip & $mask) == ($subnet & $mask);
}

function isPublicIPv4($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
    $ranges = [
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15',
        '224.0.0.0/4', '240.0.0.0/4'
    ];
    foreach ($ranges as $r) if (ipInCIDR($ip, $r)) return false;
    return $ip !== '255.255.255.255';
}

function isPublicIPv6($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return false;
    $patterns = ['/^::1$/', '/^fe80:/i', '/^fc00:/i', '/^fd00:/i', '/^::ffff:\d+\.\d+\.\d+\.\d+$/i', '/^2001:db8:/i'];
    foreach ($patterns as $p) if (preg_match($p, $ip)) return false;
    return true;
}

function isPublicIP($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return isPublicIPv4($ip);
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return isPublicIPv6($ip);
    }
    return false;
}

function resolveDomainToIPs($domain) {
    $ips = [];
    $a = @dns_get_record($domain, DNS_A);
    $aaaa = @dns_get_record($domain, DNS_AAAA);
    if ($a) foreach ($a as $r) if (isset($r['ip'])) $ips[] = $r['ip'];
    if ($aaaa) foreach ($aaaa as $r) if (isset($r['ipv6'])) $ips[] = $r['ipv6'];
    return $ips;
}

function logMessage($msg) {
    file_put_contents($GLOBALS['logFile'], $msg . "\n", FILE_APPEND | LOCK_EX);
}

// === Спиннер ===
$spinner = ['\\', '|', '/', '-'];
$spinIndex = 0;
function spin() {
    global $spinner, $spinIndex;
    echo "\r[" . $spinner[$spinIndex] . "] " . __('processing') . " ";
    $spinIndex = ($spinIndex + 1) % 4;
    usleep(100000);
    flush();
}
function clearSpinner() {
    echo "\r" . str_repeat(' ', 60) . "\r";
}

// === Парсинг аргументов и определение файлов ===
if ($argc < 2) {
    echo __($locale === 'ru' ? 'usage' : 'usage') . "\n";
    exit(1);
}

$argPath = $argv[1];
$mikrotikMode = false;
$listName = $defaultListName;

for ($i = 2; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === '--mikrotik' || $arg === '-m') {
        $mikrotikMode = true;
    } elseif (preg_match('/^--list-name=(.+)$/', $arg, $m)) {
        $listName = trim($m[1]);
        if (empty($listName) || !preg_match('/^[\w\-]+$/', $listName)) {
            die("[-] " . __("invalid_list_name", $listName) . "\n");
        }
    }
}

// === Определение списка PDF-файлов ===
$files = [];

if (strpos($argPath, '*') !== false) {
    $files = glob($argPath);
    if ($files === false || empty($files)) {
        die("[-] " . __("no_pdfs_by_mask", $argPath) . "\n");
    }
} elseif ($argc > 2) {
    for ($i = 1; $i < $argc; $i++) {
        $arg = $argv[$i];
        if (in_array($arg, ['--mikrotik', '-m']) || preg_match('/^--list-name=/i', $arg) || preg_match('/^--locale=/i', $arg)) {
            break;
        }
        if (file_exists($arg) && strtolower(pathinfo($arg, PATHINFO_EXTENSION)) === 'pdf') {
            $files[] = $arg;
        }
    }
} else {
    if (file_exists($argPath) && strtolower(pathinfo($argPath, PATHINFO_EXTENSION)) === 'pdf') {
        $files = [$argPath];
    } else {
        die("[-] " . __("file_not_found", $argPath) . "\n");
    }
}

$files = array_values(array_filter($files, function($f) {
    return file_exists($f) && strtolower(pathinfo($f, PATHINFO_EXTENSION)) === 'pdf';
}));

if (empty($files)) {
    die("[-] " . __("no_valid_pdfs") . "\n");
}

echo "[*] " . __("found_pdfs", count($files)) . "\n\n";

// === Общие данные ===
$allIPs = [];
$allSources = [];
$allFailedDomains = [];
$allIgnoredIPs = [];

// === Обработка каждого файла ===
foreach ($files as $pdfPath) {
    if (!file_exists($pdfPath)) {
        echo "[-] " . __("file_not_found_skip", $pdfPath) . "\n";
        logMessage("[-] " . __("file_not_found_skip", $pdfPath));
        continue;
    }

    echo "[*] " . __("processing_file", $pdfPath) . "\n";
    logMessage("[*] " . __("processing_file", $pdfPath));

    $escapedPath = escapeshellarg($pdfPath);
    $text = shell_exec("pdftotext $escapedPath - 2>/dev/null");

    if ($text === null || !is_string($text) || trim($text) === '') {
        $msg = "[-] Failed to extract text: $pdfPath";
        echo $msg . "\n";
        logMessage($msg);
        continue;
    }

    $pattern = '/(?:[a-zA-Z0-9\-]+|\d{1,3}|[0-9a-fA-F]{1,4})(?:\[.\](?:[a-zA-Z0-9\-]+|\d{1,3}|[0-9a-fA-F]{1,4}))+/';
    preg_match_all($pattern, $text, $matches);

    if (empty($matches[0])) {
        echo "    [~] " . __("no_addresses") . "\n";
        logMessage("[~] " . __("no_addresses") . " in $pdfPath");
        continue;
    }

    $total = count($matches[0]);
    echo "    [+] " . __("candidates_found", $total) . " — " . __("resolving") . "\n";
    logMessage("[+] " . __("candidates_found", $total) . " in $pdfPath");

    $fileIPs = [];
    $fileSources = [];
    $fileFailed = [];
    $fileIgnored = [];

    for ($i = 0; $i < $total; $i++) {
        $match = $matches[0][$i];
        $clean = str_replace('[.]', '.', $match);
        spin();

        if (filter_var($clean, FILTER_VALIDATE_IP)) {
            if (isPublicIP($clean)) {
                $fileIPs[] = $clean;
            } else {
                $fileIgnored[] = "$clean (reserved)";
            }
        } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/', $clean)) {
            $resolved = resolveDomainToIPs($clean);
            if (!empty($resolved)) {
                foreach ($resolved as $ip) {
                    if (isPublicIP($ip)) {
                        $fileIPs[] = $ip;
                        if (!isset($fileSources[$ip])) {
                            $fileSources[$ip] = $clean;
                        }
                    } else {
                        $fileIgnored[] = "$ip (from $clean)";
                    }
                }
            } else {
                $fileFailed[] = $clean;
            }
        }
    }

    clearSpinner();

    foreach ($fileIPs as $ip) {
        $allIPs[$ip] = true;
        if (!isset($allSources[$ip]) && isset($fileSources[$ip])) {
            $allSources[$ip] = $fileSources[$ip];
        }
    }
    $allFailedDomains = array_merge($allFailedDomains, $fileFailed);
    $allIgnoredIPs = array_merge($allIgnoredIPs, $fileIgnored);

    echo "    [✓] " . __("done_file") . "\n";
}

// === Финализация ===
$allIPs = array_keys($allIPs);
sort($allIPs);
$allFailedDomains = array_unique($allFailedDomains);
$allIgnoredIPs = array_unique($allIgnoredIPs);

$outputLines = [];
foreach ($allIPs as $ip) {
    $line = isset($allSources[$ip]) ? "$ip (" . $allSources[$ip] . ")" : $ip;
    $outputLines[] = $line;
}

file_put_contents($outputFile, implode("\n", $outputLines) . "\n");

echo "\n[+] " . __("done") . "\n";
echo "[*] " . __("public_ips_found", count($allIPs)) . "\n";
echo "[>] " . __("output_saved", $outputFile) . "\n\n";
foreach ($outputLines as $line) {
    echo $line . "\n";
}

// === MikroTik ===
if ($mikrotikMode) {
    $rscFile = "$listName.rsc";
    $rsc = "/ip firewall address-list\n";
    foreach ($allIPs as $ip) {
        $comment = isset($allSources[$ip]) ? "from " . $allSources[$ip] : "direct";
        $rsc .= "add address=$ip list=$listName comment=\"$comment\"\n";
    }
    file_put_contents($rscFile, $rsc);
    echo "[>] " . __("mikrotik_saved", $rscFile) . "\n";
    logMessage("[>] " . __("mikrotik_saved", $rscFile) . " (total: " . count($allIPs) . ")");
}

// === Лог ===
logMessage("[+] " . __("done"));
logMessage("[*] " . __("public_ips_found", count($allIPs)));
if ($allFailedDomains) {
    logMessage("[!] " . __("failed_resolve") . ": " . implode(', ', $allFailedDomains));
}
if ($allIgnoredIPs) {
    logMessage("[~] " . __("ignored_ips", count($allIgnoredIPs)));
}

echo "\n[✓] " . __("log_saved", $logFile) . "\n";