<?php
declare(strict_types=1);

require __DIR__.'/FixturePaths.php';
$fixtures = evidenceFixtures();
$temporary = sys_get_temp_dir().'/myproof-evidence-test-'.bin2hex(random_bytes(8));
mkdir($temporary, 0700);
mkdir($temporary.'/bundle', 0700);
$checks = 0;
$run = static function (int $expectedExit, string $mode = 'test', ?string $keyPath = null) use ($temporary, &$checks): void {
    $pipes = [];
    $process = proc_open([PHP_BINARY, dirname(__DIR__).'/bin/myproof-verify', '--bundle='.$temporary.'/bundle', '--public-key='.($keyPath ?? $temporary.'/key.hex'), '--key-id=test-vector-2026', '--mode='.$mode], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Could not start CLI test.');
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $actualExit = proc_close($process);
    ++$checks;
    if ($expectedExit !== $actualExit || ($expectedExit === 0 && !str_contains($stdout, '"verified":true')) || ($expectedExit !== 0 && !str_contains($stderr, 'Verification failed:'))) {
        throw new RuntimeException('CLI test failed with exit '.$actualExit.': '.$stderr);
    }
};
try {
    foreach (scandir($fixtures.'/test-bundle') as $name) {
        if ($name !== '.' && $name !== '..') {
            copy($fixtures.'/test-bundle/'.$name, $temporary.'/bundle/'.$name);
        }
    }
    copy($fixtures.'/test-only-public-key.hex', $temporary.'/key.hex');
    $run(0);
    $run(1, 'live');
    file_put_contents($temporary.'/wrong.hex', str_repeat('0', 64));
    $run(1, keyPath: $temporary.'/wrong.hex');
    copy($temporary.'/key.hex', $temporary.'/bundle/included.hex');
    $run(1, keyPath: $temporary.'/bundle/included.hex');
    file_put_contents($temporary.'/bundle/report.html', 'tampered');
    $run(1);
    unlink($temporary.'/bundle/report.html');
    $run(1);
    copy($fixtures.'/test-bundle/report.html', $temporary.'/outside-report.html');
    symlink($temporary.'/outside-report.html', $temporary.'/bundle/report.html');
    $run(1);
    unlink($temporary.'/bundle/report.html');
    copy($fixtures.'/test-bundle/report.html', $temporary.'/bundle/report.html');
    $events = file_get_contents($temporary.'/bundle/events.ndjson');
    file_put_contents($temporary.'/bundle/events.ndjson', rtrim($events, "\n"));
    $run(1);
    file_put_contents($temporary.'/bundle/events.ndjson', $events);
    file_put_contents($temporary.'/bundle/manifest.json', str_repeat('x', 262145));
    $run(1);
    foreach (scandir($fixtures.'/merchant-test-bundle') as $name) {
        if ($name !== '.' && $name !== '..') copy($fixtures.'/merchant-test-bundle/'.$name, $temporary.'/bundle/'.$name);
    }
    $run(0);
    $run(1, 'live');
    fwrite(STDOUT, 'PASS '.$checks." CLI checks including external pin requirement and bounded files.\n");
} finally {
    foreach (scandir($temporary.'/bundle') as $name) {
        if ($name !== '.' && $name !== '..') unlink($temporary.'/bundle/'.$name);
    }
    rmdir($temporary.'/bundle');
    foreach (scandir($temporary) as $name) {
        if ($name !== '.' && $name !== '..') unlink($temporary.'/'.$name);
    }
    rmdir($temporary);
}
