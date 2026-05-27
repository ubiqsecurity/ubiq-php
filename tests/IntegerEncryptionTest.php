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
use Ubiq\Dataset;
use Ubiq\DataTypeConfig;
use Ubiq\Encryption;

/**
 * Integration tests for the integer-typed encrypt/decrypt entry
 * points (\Ubiq\encryptInteger / \Ubiq\decryptInteger).
 *
 * Test vectors come from the shared ubiq-test-data submodule
 * (tests/ubiq-test-data/prod/dataset_types/prod-integer.json), which
 * matches the fixtures consumed by ubiq-dotnet and ubiq-java.
 *
 * To run against live credentials:
 *   - copy/symlink the credentials file into place, OR
 *   - set UBIQ_TEST_CREDENTIALS to a credentials file path AND
 *     optionally UBIQ_TEST_PROFILE (defaults to "default").
 *
 * Without credentials these tests are skipped — they DO require the
 * Ubiq backend to run end-to-end.
 *
 * @covers Ubiq\encryptInteger
 * @covers Ubiq\decryptInteger
 * @covers Ubiq\Encryption::integerToPaddedDecimal
 * @covers Ubiq\Encryption::guardIntegerDataType
 * @covers Ubiq\Decryption::guardIntegerDataType
 *
 * @uses Ubiq\Dataset
 * @uses Ubiq\DataTypeConfig
 */
final class IntegerEncryptionTest extends TestCase
{
    private const FIXTURE_PATH = __DIR__ . '/ubiq-test-data/prod/dataset_types/prod-integer.json';

    /**
     * How many rows from the fixture each test should round-trip.
     * Bigger == better coverage; smaller == faster + fewer API calls.
     */
    private const ROW_SAMPLE = 10;

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

    private function requireCredsAndFixture(): void
    {
        if (self::$creds === null) {
            $this->markTestSkipped(
                'No Ubiq credentials available — set UBIQ_TEST_CREDENTIALS '
                . 'or provide credentials via env / default file'
            );
        }
        if (!file_exists(self::FIXTURE_PATH)) {
            $this->markTestSkipped(
                'Test data submodule not initialized — '
                . 'run: git submodule update --init'
            );
        }
    }

    public function testIntegerToPaddedInputStringPositive(): void
    {
        $dataset = new Dataset('t', null, null, [
            'min_input_length' => 10,
            'input_character_set' => '0123456789',
            'passthrough' => '-',
        ]);
        $this->assertSame('0000493356', Encryption::integerToPaddedInputString(493356, $dataset));
    }

    public function testIntegerToPaddedInputStringNegative(): void
    {
        $dataset = new Dataset('t', null, null, [
            'min_input_length' => 10,
            'input_character_set' => '0123456789',
            'passthrough' => '-',
        ]);
        // Negative sign is preserved outside the pad so the FF1
        // '-' passthrough rule carries it.
        $this->assertSame('-0000493356', Encryption::integerToPaddedInputString(-493356, $dataset));
    }

    public function testIntegerToPaddedInputStringBase32(): void
    {
        // date_2keys-shaped dataset: base-32 input alphabet, 4-char min.
        // 558682 (days from epoch 0001 to 1530-09-21) renders as "H1IQ".
        $dataset = new Dataset('t', null, null, [
            'min_input_length' => 4,
            'input_character_set' => '0123456789ABCDEFGHIJKLMNOPQRSTUV',
            'passthrough' => '',
        ]);
        $this->assertSame('H1IQ', Encryption::integerToPaddedInputString(558682, $dataset));
    }

    public function testIntegerToPaddedInputStringRangeBelowMin(): void
    {
        $cfg = DataTypeConfig::fromArray(['min_input_int_value' => 0]);
        $dataset = new Dataset('t', null, null, [
            'min_input_length' => 4,
            'input_character_set' => '0123456789',
            'passthrough' => '-',
        ]);
        $dataset->data_type_config = $cfg;

        $this->expectException(\OutOfRangeException::class);
        Encryption::integerToPaddedInputString(-1, $dataset);
    }

    public function testIntegerToPaddedInputStringRangeAboveMax(): void
    {
        $cfg = DataTypeConfig::fromArray(['max_input_int_value' => 100]);
        $dataset = new Dataset('t', null, null, [
            'min_input_length' => 4,
            'input_character_set' => '0123456789',
            'passthrough' => '-',
        ]);
        $dataset->data_type_config = $cfg;

        $this->expectException(\OutOfRangeException::class);
        Encryption::integerToPaddedInputString(101, $dataset);
    }

    public function testIntFromBaseN(): void
    {
        // base-14 cipher digits round-trip with the integer64 alphabet.
        $alphabet = '0123456789ABCD';
        $this->assertSame(0, Encryption::intFromBaseN('0', $alphabet));
        $this->assertSame(13, Encryption::intFromBaseN('D', $alphabet));
        $this->assertSame(14, Encryption::intFromBaseN('10', $alphabet));
        // Round-trip a non-trivial value
        $encoded = Encryption::intToBaseN(321036445292627608, $alphabet, 0);
        $this->assertSame(321036445292627608, Encryption::intFromBaseN($encoded, $alphabet));
    }

    public function testEncryptIntegerRoundTripIntegerDatasets(): void
    {
        $this->requireCredsAndFixture();
        $rows = $this->sampleRows(self::FIXTURE_PATH, self::ROW_SAMPLE);

        $datasetsByName = [];
        foreach ($rows as $row) {
            $datasetsByName[$row['dataset']] = true;
        }
        $this->assertGreaterThan(
            0,
            count($datasetsByName),
            'Fixture sample contained no integer rows'
        );

        foreach ($rows as $row) {
            $expectedPlain = (int) $row['plaintext'];
            $expectedCipher = (int) $row['ciphertext'];

            $actualCipher = \Ubiq\encryptInteger(self::$creds, $expectedPlain, $row['dataset']);
            $this->assertSame(
                $expectedCipher,
                $actualCipher,
                "encryptInteger mismatch on dataset '" . $row['dataset']
                . "' for plaintext " . $expectedPlain
            );

            $actualPlain = \Ubiq\decryptInteger(self::$creds, $expectedCipher, $row['dataset']);
            $this->assertSame(
                $expectedPlain,
                $actualPlain,
                "decryptInteger mismatch on dataset '" . $row['dataset']
                . "' for ciphertext " . $expectedCipher
            );
        }
    }

    public function testStringEncryptRejectsIntegerDataset(): void
    {
        $this->requireCredsAndFixture();
        // Resolve any integer dataset name from the fixture so we
        // exercise the real server-side data_type tag.
        $rows = $this->sampleRows(self::FIXTURE_PATH, 1);
        $this->assertCount(1, $rows);
        $datasetName = $rows[0]['dataset'];

        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches('/data_type \'integer\'/');
        \Ubiq\encrypt(self::$creds, '0', $datasetName);
    }

    public function testEncryptIntegerForSearchReturnsArrayOfIntegers(): void
    {
        $this->requireCredsAndFixture();
        $rows = $this->sampleRows(self::FIXTURE_PATH, 1);
        $datasetName = $rows[0]['dataset'];
        $plain = (int) $rows[0]['plaintext'];

        $results = \Ubiq\encryptIntegerForSearch(self::$creds, $plain, $datasetName);

        $this->assertIsArray($results);
        $this->assertNotEmpty($results, 'expected at least one key rotation');
        foreach ($results as $cipher) {
            $this->assertIsInt($cipher);
            // Each ciphertext must decrypt back to the original
            $back = \Ubiq\decryptInteger(self::$creds, $cipher, $datasetName);
            $this->assertSame($plain, $back);
        }
    }

    public function testEncryptForSearchRejectsIntegerDataset(): void
    {
        $this->requireCredsAndFixture();
        $rows = $this->sampleRows(self::FIXTURE_PATH, 1);
        $datasetName = $rows[0]['dataset'];

        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches('/data_type \'integer\'/');
        \Ubiq\encryptForSearch(self::$creds, '0', $datasetName);
    }

    /**
     * @return array<int, array{ciphertext: string, plaintext: string, dataset: string}>
     */
    private function sampleRows(string $path, int $limit): array
    {
        $raw = json_decode(file_get_contents($path), true);
        if (!is_array($raw)) {
            $this->fail('Could not decode fixture at ' . $path);
        }
        return array_slice($raw, 0, $limit);
    }
}
