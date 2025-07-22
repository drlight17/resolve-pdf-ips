#!/usr/bin/env php
<?php

// === Настройки по умолчанию ===
$outputFile = 'output_ips.txt';
$logFile = 'resolve_log.txt';
$defaultListName = 'fstek_ban'; // Имя списка по умолчанию

// Очистим/инициализируем лог
file_put_contents($logFile, "[LOG] Старт обработки " . date('Y-m-d H:i:s') . "\n");

// === Вспомогательные функции ===

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
        '0.0.0.0/8',
        '10.0.0.0/8',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '224.0.0.0/4',
        '240.0.0.0/4',
    ];

    foreach ($privateRanges as $range) {
        if (ipInCIDR($ip, $range)) {
            return false;
        }
    }

    return $ip !== '255.255.255.255'; // broadcast
}

function isPublicIPv6($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return false;
    }

    $privatePatterns = [
        '/^::1$/',
        '/^fe80:/i',
        '/^fc00:/i',
        '/^fd00:/i',
        '/^::ffff:\d+\.\d+\.\d+\.\d+$/i',
        '/^2001:db8:/i',
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
    echo "\r[" . $spinner[$spinIndex] . "] Обработка... (Ctrl+C для остановки) ";
    $spinIndex = ($spinIndex + 1) % 4;
    usleep(100000); // 0.1 сек
    flush();
}

function clearSpinner() {
    echo "\r" . str_repeat(' ', 60) . "\r";
}

// === Парсинг аргументов ===
if ($argc < 2) {
    echo "Использование: php resolve_pdf_ips.php <путь_к_pdf> [опции]\n";
    echo "Опции:\n";
    echo "  --mikrotik, -m           Создать файл fstek_ban.rsc для MikroTik\n";
    echo "  --list-name=<имя>        Указать имя списка в MikroTik (по умолчанию: fstek_ban)\n";
    echo "\nПримеры:\n";
    echo "  php resolve_pdf_ips.php report.pdf\n";
    echo "  php resolve_pdf_ips.php report.pdf --mikrotik\n";
    echo "  php resolve_pdf_ips.php report.pdf -m --list-name=malicious_ips\n";
    exit(1);
}

$pdfPath = $argv[1];

$mikrotikMode = false;
$listName = $defaultListName; // по умолчанию

for ($i = 2; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === '--mikrotik' || $arg === '-m') {
        $mikrotikMode = true;
    } elseif (preg_match('/^--list-name=(.+)$/', $arg, $matches)) {
        $listName = trim($matches[1]);
        if (empty($listName)) {
            die("[-] Имя списка не может быть пустым.\n");
        }
        // Безопасность: разрешим только буквы, цифры, подчёркивания и дефисы
        if (!preg_match('/^[\w\-]+$/', $listName)) {
            die("[-] Недопустимое имя списка: $listName. Используйте буквы, цифры, _ или -\n");
        }
    }
}

// === Начало обработки ===
echo "[*] Обработка файла: $pdfPath\n";
logMessage("[*] Обработка файла: $pdfPath");

if (!file_exists($pdfPath)) {
    $msg = "[-] Файл не найден: $pdfPath";
    echo $msg . "\n";
    logMessage($msg);
    exit(1);
}

$which = shell_exec('which pdftotext');
if (empty(trim($which))) {
    $msg = "[-] Утилита pdftotext не установлена. Установите: sudo apt install poppler-utils";
    echo $msg . "\n";
    logMessage($msg);
    exit(1);
}

echo "[*] Извлечение текста из PDF...\n";
logMessage("[*] Извлечение текста...");

$text = shell_exec("pdftotext \"$pdfPath\" -");
if ($text === null || trim($text) === '') {
    $msg = "[-] Не удалось извлечь текст из PDF.";
    echo $msg . "\n";
    logMessage($msg);
    exit(1);
}

echo "[+] Текст извлечён. Поиск адресов...\n";
logMessage("[+] Текст извлечён.");

$pattern = '/(?:[a-zA-Z0-9\-]+|\d{1,3}|[0-9a-fA-F]{1,4})(?:\[.\](?:[a-zA-Z0-9\-]+|\d{1,3}|[0-9a-fA-F]{1,4}))+/';
preg_match_all($pattern, $text, $matches);

if (empty($matches[0])) {
    echo "[!] Адреса не найдены.\n";
    logMessage("[!] Адреса не найдены.");
    exit(0);
}

$total = count($matches[0]);
echo "[*] Найдено кандидатов: $total\n";
logMessage("[*] Найдено кандидатов: $total");

echo "[*] Разрешение доменов и фильтрация IP...\n";
logMessage("[*] Начало разрешения доменов.");

$ips = [];
$failedDomains = [];
$ignoredIPs = [];

// === Обработка ===
for ($i = 0; $i < $total; $i++) {
    $match = $matches[0][$i];
    $clean = str_replace('[.]', '.', $match);
    spin();

    if (filter_var($clean, FILTER_VALIDATE_IP)) {
        if (isPublicIP($clean)) {
            $ips[] = $clean;
        } else {
            $ignoredIPs[] = "$clean (служебный)";
        }
    } elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/', $clean)) {
        $resolvedIPs = resolveDomainToIPs($clean);
        if (!empty($resolvedIPs)) {
            foreach ($resolvedIPs as $ip) {
                if (isPublicIP($ip)) {
                    $ips[] = $ip;
                } else {
                    $ignoredIPs[] = "$ip (из домена $clean)";
                }
            }
        } else {
            $failedDomains[] = $clean;
        }
    }
}

clearSpinner();

// Уникальность
$ips = array_unique($ips);
sort($ips);

// Сохранение основного списка
file_put_contents($outputFile, implode("\n", $ips) . "\n");

// Вывод
echo "\n[+] Обработка завершена.\n";
echo "[*] Найдено публичных IP-адресов: " . count($ips) . "\n";
echo "[>] Результат сохранён в: $outputFile\n\n";

foreach ($ips as $ip) {
    echo $ip . "\n";
}

// === Экспорт в MikroTik (если включён) ===
if ($mikrotikMode) {
    $rscFile = $listName . '.rsc'; // Например: malicious_ips.rsc
    $rscContent = "/ip firewall address-list\n";
    foreach ($ips as $ip) {
        $rscContent .= "add address=$ip list=$listName comment=\"autogen from PDF\"\n";
    }
    file_put_contents($rscFile, $rscContent);
    echo "[>] Файл для MikroTik сохранён: $rscFile\n";
    logMessage("[>] Создан файл MikroTik: $rscFile (список: $listName, записей: " . count($ips) . ")");
}

// === Логирование ===
logMessage("[+] Обработка завершена.");
logMessage("[*] Публичных IP: " . count($ips));
if (!empty($failedDomains)) {
    logMessage("[!] Не разрешились домены: " . implode(', ', $failedDomains));
}
if (!empty($ignoredIPs)) {
    logMessage("[~] Проигнорировано служебных IP: " . count($ignoredIPs));
}

echo "\n[✓] Лог сохранён: $logFile\n";
