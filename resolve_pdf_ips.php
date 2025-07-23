#!/usr/bin/env php
<?php

// === Настройки ===
$outputFile = 'output_ips.txt';
$logFile = 'resolve_log.txt';
$defaultListName = 'fstek_ban';
$langDir = 'lang';

// === Определение языка ===
function detectLocale($argv) {
    // Проверяем аргумент --locale
    foreach ($argv as $arg) {
        if (preg_match('/^--locale=(en|ru)$/', $arg, $matches)) {
            return $matches[1];
        }
    }

    // Автоопределение по системе
    $locale = getenv('LC_ALL') ?: getenv('LANG');
    if ($locale && strpos($locale, 'ru') === 0) {
        return 'ru';
    }
    return 'en'; // fallback
}

$locale = detectLocale($argv);
$langFile = "$langDir/$locale.json";

if (!file_exists($langFile)) {
    $langFile = "$langDir/en.json"; // fallback
}

$LANG = json_decode(file_get_contents($langFile), true);
if (!$LANG) {
    die("Error loading language file: $langFile\n");
}

// Форматированная строка (printf-подобно)
function __($key, ...$args) {
    global $LANG;
    $msg = $LANG[$key] ?? $key;
    if (!empty($args)) {
        return vsprintf($msg, $args);
    }
    return $msg;
}

// === Вспомогательные функции (без изменений) ===

function ipInCIDR($ip, $cidr) {
    list($subnet, $bits) = explode('/', $cidr);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    return ($ip & $mask) == ($subnet & $mask);
}

function isPublicIPv4($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }

    $privateRanges = [
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15',
        '224.0.0.0/4', '240.0.0.0/4',
    ];

    foreach ($privateRanges as $range) {
        if (ipInCIDR($ip, $range)) {
            return false;
        }
    }

    return $ip !== '255.255.255.255';
}

function isPublicIPv6($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return false;
    }

    $privatePatterns = [
        '/^::1$/', '/^fe80:/i', '/^fc00:/i', '/^fd00:/i',
        '/^::ffff:\d+\.\d+\.\d+\.\d+$/i', '/^2001:db8:/i',
    ];

    foreach ($privatePatterns as $pattern) {
        if (preg_match($pattern, $ip)) {
            return false;
        }
    }

    return true;
}

function isPublicIP($ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return isPublicIPv4($ip);
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return isPublicIPv6($ip);
    }
    return false;
}

function resolveDomainToIPs($domain) {
    $ips = [];
    $aRecords = @dns_get_record($domain, DNS_A);
    if (!empty($aRecords)) {
        foreach ($aRecords as $record) {
            if (isset($record['ip'])) {
                $ips[] = $record['ip'];
            }
        }
    }
    $aaaaRecords = @dns_get_record($domain, DNS_AAAA);
    if (!empty($aaaaRecords)) {
        foreach ($aaaaRecords as $record) {
            if (isset($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }
    }
    return $ips;
}

function logMessage($message) {
    file_put_contents('resolve_log.txt', $message . "\n", FILE_APPEND | LOCK_EX);
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

// === Парсинг аргументов ===
if ($argc < 2) {
    echo __($locale === 'ru' ? 'usage' : 'usage') . "\n";
    exit(1);
}

$pdfPath = $argv[1];

$mikrotikMode = false;
$listName = $defaultListName;

for ($i = 2; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === '--mikrotik' || $arg === '-m') {
        $mikrotikMode = true;
    } elseif (preg_match('/^--list-name=(.+)$/', $arg, $matches)) {
        $listName = trim($matches[1]);
        if (empty($listName) || !preg_match('/^[\w\-]+$/', $listName)) {
            die(__("Invalid list name: %s\n", $listName));
        }
    }
}

// === Логирование старта ===
logMessage("[LOG] " . __('processing_file', $pdfPath));

// === Обработка ===
echo "[*] " . __('processing_file', $pdfPath) . "\n";

if (!file_exists($pdfPath)) {
    $msg = "[-] " . __('file_not_found', $pdfPath);
    echo $msg . "\n";
    logMessage($msg);
    exit(1);
}

$which = shell_exec('which pdftotext');
if (empty(trim($which))) {
    $msg = "[-] " . __('pdftotext_missing');
    echo $msg . "\n";
    logMessage($msg);
    exit(1);
}

echo "[*] " . __('extracting_text') . "\n";
logMessage("[*] " . __('extracting_text'));

$text = shell_exec("pdftotext \"$pdfPath\" -");
if ($text === null || trim($text) === '') {
    $msg = "[-] " . __('extracting_text') . " — failed";
    echo $msg . "\n";
    logMessage($msg);
    exit(1);
}

echo "[+] " . __('text_extracted') . "\n";
logMessage("[+] " . __('text_extracted'));

$pattern = '/(?:[a-zA-Z0-9\-]+|\d{1,3}|[0-9a-fA-F]{1,4})(?:\[.\](?:[a-zA-Z0-9\-]+|\d{1,3}|[0-9a-fA-F]{1,4}))+/';
preg_match_all($pattern, $text, $matches);

if (empty($matches[0])) {
    echo "[!] " . __('no_addresses') . "\n";
    logMessage("[!] " . __('no_addresses'));
    exit(0);
}

$total = count($matches[0]);
echo "[*] " . __('candidates_found', $total) . "\n";
logMessage("[*] " . __('candidates_found', $total));

echo "[*] " . __('resolving') . "\n";
logMessage("[*] " . __('resolving'));

$ips = [];
$failedDomains = [];
$ignoredIPs = [];

for ($i = 0; $i < $total; $i++) {
    $match = $matches[0][$i];
    $clean = str_replace('[.]', '.', $match);
    spin();

    if (filter_var($clean, FILTER_VALIDATE_IP)) {
        if (isPublicIP($clean)) {
            $ips[] = $clean;
        } else {
            $ignoredIPs[] = "$clean (reserved)";
        }
    } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/', $clean)) {
        $resolvedIPs = resolveDomainToIPs($clean);
        if (!empty($resolvedIPs)) {
            foreach ($resolvedIPs as $ip) {
                if (isPublicIP($ip)) {
                    $ips[] = $ip;
                } else {
                    $ignoredIPs[] = "$ip (from $clean)";
                }
            }
        } else {
            $failedDomains[] = $clean;
        }
    }
}

clearSpinner();

$ips = array_unique($ips);
sort($ips);

file_put_contents($outputFile, implode("\n", $ips) . "\n");

echo "\n[+] " . __('done') . "\n";
echo "[*] " . __('public_ips_found', count($ips)) . "\n";
echo "[>] " . __('output_saved', $outputFile) . "\n\n";

foreach ($ips as $ip) {
    echo $ip . "\n";
}

if ($mikrotikMode) {
    $rscFile = $listName . '.rsc';
    $rscContent = "/ip firewall address-list\n";
    foreach ($ips as $ip) {
        $rscContent .= "add address=$ip list=$listName comment=\"autogen from PDF\"\n";
    }
    file_put_contents($rscFile, $rscContent);
    echo "[>] " . __('mikrotik_saved', $rscFile) . "\n";
    logMessage("[>] " . __('mikrotik_saved', $rscFile) . " (count: " . count($ips) . ")");
}

logMessage("[+] " . __('done'));
logMessage("[*] " . __('public_ips_found', count($ips)));
if (!empty($failedDomains)) {
    logMessage("[!] " . __('failed_resolve') . ": " . implode(', ', $failedDomains));
}
if (!empty($ignoredIPs)) {
    logMessage("[~] " . __('ignored_ips', count($ignoredIPs)));
}

echo "\n[✓] " . __('log_saved', $logFile) . "\n";