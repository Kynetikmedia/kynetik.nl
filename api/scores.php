<?php
/**
 * Kynetik coming soon: highscores voor het balspel.
 *
 * GET  api/scores.php            -> top 10
 * GET  api/scores.php?token=1    -> start-token voor een nieuwe ronde
 * POST api/scores.php            -> {name, score, token} opslaan
 *
 * Data staat BUITEN de websitemap (../../kynetik-data), zodat een Git-deploy
 * hem nooit overschrijft en niemand het bestand direct kan downloaden.
 * Een naam weghalen: open kynetik-data/scores.json in Plesk > Files en
 * verwijder de regel.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const MAX_ENTRIES   = 10;
const NAME_MIN      = 2;
const NAME_MAX      = 16;
const SCORE_MAX     = 500;
const SEC_PER_POINT = 0.35;   // een tik kost minstens zoveel tijd
const TOKEN_TTL     = 1800;   // een ronde mag max 30 minuten duren
const RATE_SECONDS  = 10;     // max 1 inzending per 10 s per bezoeker

$dataDir = dirname(__DIR__, 2) . '/kynetik-data';
if (!is_dir($dataDir) && !@mkdir($dataDir, 0750, true)) {
    fail(500, 'Opslag niet beschikbaar');
}
$scoresFile = $dataDir . '/scores.json';
$rateFile   = $dataDir . '/rate.json';
$secretFile = $dataDir . '/secret.key';

if (!is_file($secretFile)) {
    file_put_contents($secretFile, bin2hex(random_bytes(32)), LOCK_EX);
    @chmod($secretFile, 0600);
}
$secret = trim((string) file_get_contents($secretFile));

function fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}

function readJson(string $file): array {
    if (!is_file($file)) return [];
    $data = json_decode((string) file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function topList(array $scores): array {
    usort($scores, fn($a, $b) => $b['score'] <=> $a['score'] ?: $a['t'] <=> $b['t']);
    return array_map(fn($s) => ['name' => $s['name'], 'score' => $s['score']],
        array_slice($scores, 0, MAX_ENTRIES));
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    if (isset($_GET['token'])) {
        $t = (string) time();
        echo json_encode(['ok' => true, 'token' => $t . '.' . hash_hmac('sha256', $t, $secret)]);
        exit;
    }
    echo json_encode(['ok' => true, 'top' => topList(readJson($scoresFile))]);
    exit;
}

if ($method !== 'POST') fail(405, 'Niet toegestaan');

$in = json_decode((string) file_get_contents('php://input'), true);
if (!is_array($in)) fail(400, 'Ongeldige invoer');

// Naam: letters, cijfers, spatie en . _ - ; geen HTML.
$name = trim(preg_replace('/\s+/u', ' ', (string) ($in['name'] ?? '')));
$len  = mb_strlen($name);
if ($len < NAME_MIN || $len > NAME_MAX || !preg_match('/^[\p{L}\p{N} ._\-]+$/u', $name)) {
    fail(422, 'Gebruik 2 tot 16 letters of cijfers');
}
$blocked = ['kanker', 'tering', 'tyfus', 'hoer', 'neuk', 'kut', 'lul', 'nazi', 'hitler', 'nigger', 'nigga', 'fuck', 'cunt', 'bitch', 'slet', 'mongool', 'homo', 'flikker'];
$plain = mb_strtolower(preg_replace('/[^\p{L}]/u', '', $name));
foreach ($blocked as $w) {
    if (str_contains($plain, $w)) fail(422, 'Kies een andere naam');
}

// Score + token: ronde moet echt zo lang geduurd hebben.
$score = filter_var($in['score'] ?? null, FILTER_VALIDATE_INT);
if ($score === false || $score < 1 || $score > SCORE_MAX) fail(422, 'Ongeldige score');
[$ts, $sig] = array_pad(explode('.', (string) ($in['token'] ?? ''), 2), 2, '');
if (!ctype_digit($ts) || !hash_equals(hash_hmac('sha256', $ts, $secret), $sig)) fail(403, 'Ongeldige ronde');
$elapsed = time() - (int) $ts;
if ($elapsed > TOKEN_TTL || $elapsed + 1 < $score * SEC_PER_POINT) fail(403, 'Die score is te snel');

// Rate limit per bezoeker (IP alleen gehasht opgeslagen, wordt na een uur weggegooid).
$ipHash = hash_hmac('sha256', $_SERVER['REMOTE_ADDR'] ?? '', $secret);
$now = time();

$fh = fopen($scoresFile, 'c+');
if (!$fh || !flock($fh, LOCK_EX)) fail(500, 'Opslag bezet, probeer opnieuw');

$rate = array_filter(readJson($rateFile), fn($t) => $now - $t < 3600);
if (isset($rate[$ipHash]) && $now - $rate[$ipHash] < RATE_SECONDS) {
    flock($fh, LOCK_UN); fail(429, 'Even rustig aan, probeer het zo opnieuw');
}
$rate[$ipHash] = $now;
file_put_contents($rateFile, json_encode($rate), LOCK_EX);

$scores = json_decode(stream_get_contents($fh) ?: '[]', true);
if (!is_array($scores)) $scores = [];

// Zelfde naam: alleen de beste score bewaren.
$key = mb_strtolower($name);
$existing = null;
foreach ($scores as $i => $s) if (mb_strtolower($s['name']) === $key) $existing = $i;
if ($existing !== null) {
    if ($scores[$existing]['score'] >= $score) {
        flock($fh, LOCK_UN);
        echo json_encode(['ok' => true, 'kept' => true, 'top' => topList($scores)]);
        exit;
    }
    $scores[$existing] = ['name' => $name, 'score' => $score, 't' => $now];
} else {
    $scores[] = ['name' => $name, 'score' => $score, 't' => $now];
}
// Bewaar ruim meer dan de top 10, zodat het bestand klein blijft maar niet te krap.
usort($scores, fn($a, $b) => $b['score'] <=> $a['score'] ?: $a['t'] <=> $b['t']);
$scores = array_slice($scores, 0, 100);

ftruncate($fh, 0);
rewind($fh);
fwrite($fh, json_encode($scores, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
fflush($fh);
flock($fh, LOCK_UN);
fclose($fh);

$rank = 1 + count(array_filter($scores, fn($s) => $s['score'] > $score));
echo json_encode(['ok' => true, 'rank' => $rank, 'top' => topList($scores)]);
