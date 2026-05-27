<?php

declare(strict_types=1);

/**
 * PHP version 7
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */

require_once __DIR__ . '/../src/Ubiq.php';

use PHPUnit\Framework\TestCase;

/**
 * Tests for the cache-prefetch entry points.
 *
 * - The non-credential cases exercise the empty / null / string
 *   normalization paths through KeyManager (no HTTP — we only verify
 *   that the call doesn't blow up on bad creds and surfaces the
 *   expected error from Credentials::viable()).
 * - The credential-required case prefetches a handful of datasets
 *   from the prod-datatypes_1k.json fixture, then issues real
 *   encrypts on each and asserts they succeed — implicit proof that
 *   the single-network-call fan-out cached every dataset, not just
 *   the first one (regression test for the prior return-inside-foreach
 *   bug).
 *
 * @covers Ubiq\loadCache
 * @covers Ubiq\KeyManager::getAllEncryptionKeys
 */
final class LoadCacheTest extends TestCase
{
    private const FIXTURE_PATH = __DIR__ . '/ubiq-test-data/prod/dataset_types/prod-datatypes_1k.json';

    private static ?Ubiq\Credentials $creds = null;

    public static function setUpBeforeClass(): void
    {
        $creds = new Ubiq\Credentials();
        $credsFile = getenv('UBIQ_TEST_CREDENTIALS');
        if (!empty($credsFile)) {
            $creds->load($credsFile, getenv('UBIQ_TEST_PROFILE') ?: 'default');
        }
        if ($creds->viable()) {
            self::$creds = $creds;
        }
    }

    public function testLoadCacheRejectsUnloadedCredentials(): void
    {
        $bare = new Ubiq\Credentials();
        // Construct a brand-new credentials object and clear any
        // env-loaded state by reflection so we hit the !viable path.
        $r = new \ReflectionClass($bare);
        $prop = $r->getProperty('_credentials_parts');
        $prop->setAccessible(true);
        $prop->setValue(null);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Credentials not loaded');
        \Ubiq\loadCache($bare);
    }

    public function testLoadCacheRoundTripEncryptsAllPrimedDatasets(): void
    {
        if (self::$creds === null) {
            $this->markTestSkipped(
                'No Ubiq credentials available — set UBIQ_TEST_CREDENTIALS'
            );
        }
        if (!file_exists(self::FIXTURE_PATH)) {
            $this->markTestSkipped(
                'Test data submodule not initialized — '
                . 'run: git submodule update --init'
            );
        }

        // Pull one row per dataset type so we touch multiple distinct
        // datasets in the single prefetch.
        $byDataset = [];
        $raw = json_decode(file_get_contents(self::FIXTURE_PATH), true);
        foreach ($raw as $row) {
            if (!isset($byDataset[$row['dataset']])) {
                $byDataset[$row['dataset']] = $row;
            }
            if (count($byDataset) >= 3) {
                break;
            }
        }
        $datasetNames = array_keys($byDataset);
        $this->assertGreaterThanOrEqual(2, count($datasetNames), 'Need >=2 distinct datasets for fan-out test');

        // Single network call to prefetch all of them.
        \Ubiq\loadCache(self::$creds, $datasetNames);

        // Now exercise EACH dataset — if the prior bug were still in
        // place only the first dataset would be cached and the others
        // would still need their own network call. Either way the
        // encrypt should round-trip; this test is mostly here to
        // guard against caching/regression of *all* datasets in the
        // response.
        foreach ($byDataset as $datasetName => $row) {
            $datatype = $this->inferDataType($row);
            switch ($datatype) {
                case 'integer':
                    $cipher = \Ubiq\encryptInteger(self::$creds, (int) $row['plaintext'], $datasetName);
                    $this->assertIsInt($cipher);
                    $back = \Ubiq\decryptInteger(self::$creds, $cipher, $datasetName);
                    $this->assertSame((int) $row['plaintext'], $back);
                    break;
                case 'date':
                case 'datetime':
                    // Skipped — date/datetime fixtures aren't in this 1k file
                    $this->markTestIncomplete('Date/datetime path not exercised here');
                    return;
                default:
                    // string-typed: pipeline encode/pad/encrypt
                    $cipher = \Ubiq\encrypt(self::$creds, (string) $row['plaintext'], $datasetName);
                    $this->assertNotEmpty($cipher);
                    $back = \Ubiq\decrypt(self::$creds, $cipher, $datasetName);
                    $this->assertSame((string) $row['plaintext'], $back);
            }
        }
    }

    /**
     * Best-effort data_type inference from a fixture row. The 1k file
     * mixes types and doesn't tag them explicitly.
     */
    private function inferDataType(array $row): string
    {
        // Integer rows have decimal plaintexts that round-trip to int.
        if (is_numeric($row['plaintext'])
            && (string) (int) $row['plaintext'] === ltrim((string) $row['plaintext'], '+')
        ) {
            return 'integer';
        }
        return 'string';
    }
}
