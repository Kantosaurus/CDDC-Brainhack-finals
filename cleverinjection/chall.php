<?php
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Time Capsule Console</title>
    <style>
        body {
            background: url('https://images.unsplash.com/photo-1526378722484-cc2b2ddfc1a6?ixlib=rb-4.0.3&auto=format&fit=crop&w=1950&q=80') no-repeat center center fixed;
            background-size: cover;
            font-family: 'Courier New', Courier, monospace;
            color: #00ffcc;
            margin: 0;
            padding: 0;
        }
        .console {
            background: rgba(0,0,0,0.85);
            border: 2px solid #00ffcc;
            border-radius: 10px;
            padding: 30px;
            margin: 10% auto;
            width: 500px;
            box-shadow: 0 0 20px #00ffcc;
        }
        h2 {
            text-align: center;
            animation: flicker 2s infinite;
        }
        @keyframes flicker {
            0% { opacity: 1; }
            50% { opacity: 0.6; }
            100% { opacity: 1; }
        }
        label, input, button {
            display: block;
            width: 100%;
            margin-top: 15px;
            font-size: 1.1em;
        }
        input {
            padding: 10px;
            background: #000;
            border: 1px solid #00ffcc;
            color: #00ffcc;
        }
        button {
            background: #00ffcc;
            color: #000;
            font-weight: bold;
            padding: 10px;
            border: none;
            cursor: pointer;
        }
        button:hover {
            background: #00ffee;
        }
    </style>
</head>
<body>
    <div class="console">
        <h2>🚀 Time Capsule Entry</h2>
        <form method="POST">
            <label for="payload">🕰 Time Payload:</label>
            <input type="text" id="payload" name="payload" placeholder="e.g., 2088-Mars-Colony" required>
            <button type="submit">Store in Spacetime</button>
        </form>
    </div>
</body>
</html>
<?php
    exit;
}

$host = 'db';
$port = 5432;
$dbname = 'postgres';
$user = 'postgres';
$password = 'password';
$conn_string = "host=$host port=$port dbname=$dbname user=$user password=$password";
$conn = pg_connect($conn_string);

if (!$conn) {
    http_response_code(500);
    die("Database connection failed: " . pg_last_error());
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['payload'])) {
    $raw_payload = $_POST['payload'];
    $escaped = pg_escape_string($conn, $raw_payload);
    $quoted = "'" . $escaped . "'";
    $sql = "INSERT INTO test (id) VALUES ($quoted);";

    $tmpfile = tempnam(sys_get_temp_dir(), 'sql_');
    file_put_contents($tmpfile, $sql);
    putenv("PGPASSWORD=$password");

    $cmd = sprintf(
        'psql -U %s -d %s -h %s -t -A -e -f %s 2>&1',
        escapeshellarg($user),
        escapeshellarg($dbname),
        escapeshellarg($host),
        escapeshellarg($tmpfile)
    );

    exec($cmd, $output, $exitCode);

    pg_close($conn);
    unlink($tmpfile);

    echo "<pre style='background:black; color:#00ffcc; padding:20px;'>";
    echo "🔐 Time Capsule Result:\n";
    echo htmlspecialchars(implode("\n", $output)) . "\n";

    if ($exitCode !== 0) {
        http_response_code(500);
        echo "⛔ Failed to store the time payload\n";
        exit;
    }

    echo "✅ Time payload successfully stored: " . htmlspecialchars($raw_payload) . "\n";
    echo "</pre>";
} else {
    http_response_code(400);
    echo "⚠️ POST 'payload' is required.";
}
?>
