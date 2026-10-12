<?php
declare(strict_types=1);

namespace MyProof\Evidence;

/** Local archive decoding with explicit compressed, entry, path and expanded-byte budgets. */
final class BoundedZip
{
    /** @return array<string,string> */
    public static function read(string $bytes): array
    {
        if (!class_exists(\ZipArchive::class) || strlen($bytes) < 1 || strlen($bytes) > CollectionSchema::MAX_ARCHIVE_BYTES) {
            throw new EvidenceException('Collection ZIP support or archive size is invalid.');
        }
        $path = tempnam(sys_get_temp_dir(), 'myproof-verify-');
        if ($path === false) {
            throw new EvidenceException('Verifier scratch file unavailable.');
        }
        chmod($path, 0600);
        $zip = new \ZipArchive();
        $opened = false;
        try {
            if (file_put_contents($path, $bytes) !== strlen($bytes) || $zip->open($path, \ZipArchive::RDONLY) !== true) {
                throw new EvidenceException('Cannot open collection archive.');
            }
            $opened = true;
            if ($zip->numFiles < 1 || $zip->numFiles > 18) {
                throw new EvidenceException('Archive entry bound exceeded.');
            }
            $files = [];
            $total = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if ($stat === false || !preg_match('/\A[a-z0-9][a-z0-9_-]{0,63}\.(json|ndjson|ed25519|html|pdf|txt)\z/', $stat['name'])
                    || isset($files[$stat['name']]) || !in_array($stat['comp_method'], [0, 8], true)
                    || $stat['size'] < 0 || $stat['size'] > CollectionSchema::MAX_ARTIFACT_BYTES
                    || ($total += $stat['size']) > CollectionSchema::MAX_ARTIFACT_BYTES + CollectionSchema::MAX_SEGMENT_BYTES + CollectionSchema::MAX_INDEX_BYTES) {
                    throw new EvidenceException('Invalid, duplicate or oversized archive entry.');
                }
                $opsys = $attributes = 0;
                if (!$zip->getExternalAttributesIndex($i, $opsys, $attributes) || ($opsys === 3 && (($attributes >> 16) & 0170000) === 0120000)) {
                    throw new EvidenceException('Archive symlink is prohibited.');
                }
                $entry = $zip->getFromIndex($i, $stat['size'] + 1);
                if (!is_string($entry) || strlen($entry) !== $stat['size']) {
                    throw new EvidenceException('Archive entry cannot be read exactly.');
                }
                $files[$stat['name']] = $entry;
            }
            return $files;
        } finally {
            if ($opened) {
                $zip->close();
            }
            unlink($path);
        }
    }

    public static function exactFiles(array $files, array $expected): void
    {
        $actual = array_keys($files);
        sort($actual);
        sort($expected);
        if ($actual !== $expected) {
            throw new EvidenceException('Archive contains missing or unbound files.');
        }
    }
}
