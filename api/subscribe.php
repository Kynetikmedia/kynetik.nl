<?php
/**
 * Kynetik coming soon: mail-opt-in ("hou me op de hoogte").
 *
 * POST api/subscribe.php  {email, name?, consent: true}
 *
 * Adressen komen in ../../kynetik-data/aanmeldingen.csv, BUITEN de websitemap.
 * Openen kan in Plesk > Files, of downloaden en in Excel/Mailchimp importeren.
 * Iemand afmelden: haal de regel weg uit het CSV-bestand.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const CONSENT_TEXT = 'Mail me als Kynetik live gaat en als iemand mijn record verbreekt (v1)';
const RATE_SECONDS = 20;

function fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}
// Voorkomt dat Excel een waarde als formule uitvoert.
function csvSafe(string $v): string {
    return preg_match('/^[=+\-@\t\r]/', $v) ? "'" . $v : $v;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail(405, 'Niet toegestaan');

$dataDir = dirname(__DIR__, 2) . '/kynetik-data';
if (!is_dir($dataDir) && !@mkdir($dataDir, 0750, true)) fail(500, 'Opslag niet beschikbaar');
$file       = $dataDir . '/aanmeldingen.csv';
$rateFile   = $dataDir . '/rate-subscribe.json';
$secretFile = $dataDir . '/secret.key';
if (!is_file($secretFile)) {
    file_put_contents($secretFile, bin2hex(random_bytes(32)), LOCK_EX);
    @chmod($secretFile, 0600);
}
$secret = trim((string) file_get_contents($secretFile));

$in = json_decode((string) file_get_contents('php://input'), true);
if (!is_array($in)) fail(400, 'Ongeldige invoer');

// Toestemming moet expliciet zijn meegestuurd (de bezoeker klikte zelf op de knop).
if (($in['consent'] ?? false) !== true) fail(422, 'Zonder toestemming kunnen we je niet mailen');

// Honeypot: echte bezoekers zien dit veld niet.
if (!empty($in['website'])) { echo json_encode(['ok' => true]); exit; }

$email = strtolower(trim((string) ($in['email'] ?? '')));
if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) fail(422, 'Dat mailadres klopt niet helemaal');

$name = trim(preg_replace('/\s+/u', ' ', (string) ($in['name'] ?? '')));
if ($name !== '' && (mb_strlen($name) > 16 || !preg_match('/^[\p{L}\p{N} ._\-]+$/u', $name))) $name = '';
$score = filter_var($in['score'] ?? 0, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 500]]) ?: 0;

// Rate limit per bezoeker (IP alleen gehasht, na een uur weg).
$ipHash = hash_hmac('sha256', $_SERVER['REMOTE_ADDR'] ?? '', $secret);
$now = time();
$rate = is_file($rateFile) ? (json_decode((string) file_get_contents($rateFile), true) ?: []) : [];
$rate = array_filter($rate, fn($t) => $now - $t < 3600);
if (isset($rate[$ipHash]) && $now - $rate[$ipHash] < RATE_SECONDS) fail(429, 'Even rustig aan, probeer het zo opnieuw');
$rate[$ipHash] = $now;
file_put_contents($rateFile, json_encode($rate), LOCK_EX);

$fh = fopen($file, 'c+');
if (!$fh || !flock($fh, LOCK_EX)) fail(500, 'Opslag bezet, probeer opnieuw');

// Al aangemeld? Dan niets dubbel opslaan.
$isNew = filesize($file) === 0;
if (!$isNew) {
    while (($row = fgetcsv($fh, 0, ';', '"', '')) !== false) {
        if (isset($row[0]) && strtolower(ltrim($row[0], "'")) === $email) {
            flock($fh, LOCK_UN); fclose($fh);
            echo json_encode(['ok' => true, 'already' => true]);
            exit;
        }
    }
}
fseek($fh, 0, SEEK_END);
if ($isNew) fputcsv($fh, ['email', 'naam', 'score', 'aangemeld_op', 'toestemming'], ';', '"', '');
fputcsv($fh, [csvSafe($email), csvSafe($name), (string) $score, date('Y-m-d H:i'), CONSENT_TEXT], ';', '"', '');
fflush($fh);
flock($fh, LOCK_UN);
fclose($fh);

echo json_encode(['ok' => true]);
