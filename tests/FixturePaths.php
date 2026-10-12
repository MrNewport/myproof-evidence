<?php
declare(strict_types=1);

function evidenceFixtures(): string
{
    $package = dirname(__DIR__).'/spec/evidence/fixtures';
    $monorepo = dirname(__DIR__, 3).'/spec/evidence/fixtures';

    if (is_file($package.'/canonical-vectors.json')) {
        return $package;
    }
    $application = dirname(__DIR__, 3).'/composer.json';
    if (is_file($application)
        && json_decode(file_get_contents($application), true)['name'] === 'myproof/application'
        && is_file($monorepo.'/canonical-vectors.json')) {
        return $monorepo;
    }

    throw new RuntimeException('Authoritative evidence fixtures are missing.');
}
