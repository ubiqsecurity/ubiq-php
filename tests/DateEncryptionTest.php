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
 * Integration tests for the date / datetime typed encrypt/decrypt
 * entry points (\Ubiq\encryptDate / \Ubiq\decryptDate /
 * \Ubiq\encryptDateTime / \Ubiq\decryptDateTime).
 *
 * Test vectors come from the shared ubiq-test-data submodule
 * (tests/ubiq-test-data/prod/dataset_types/prod-dates.json).
 *
 * @covers Ubiq\encryptDate
 * @covers Ubiq\decryptDate
 * @covers Ubiq\encryptDateTime
 * @covers Ubiq\decryptDateTime
 * @covers Ubiq\Encryption::guardDateDataType
 * @covers Ubiq\Encryption::guardDateTimeDataType
 * @covers Ubiq\Encryption::daysBetween
 * @covers Ubiq\Encryption::secondsBetween
 *
 * @uses Ubiq\Dataset
 * @uses Ubiq\DataTypeConfig
 */
final class DateEncryptionTest extends TestCase
{
    private const FIXTURE_PATH = __DIR__ . '/ubiq-test-data/prod/dataset_types/prod-dates.json';

    private const ROW_SAMPLE = 5;

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
                'No Ubiq credentials available — set UBIQ_TEST_CREDENTIALS'
            );
        }
        if (!file_exists(self::FIXTURE_PATH)) {
            $this->markTestSkipped(
                'Test data submodule not initialized — '
                . 'run: git submodule update --init'
            );
        }
    }

    public function testDaysBetweenSameDayIsZero(): void
    {
        $epoch = new \DateTimeImmutable('2024-01-01T00:00:00Z');
        $date = new \DateTimeImmutable('2024-01-01T23:59:59Z');
        $this->assertSame(0, Encryption::daysBetween($epoch, $date));
    }

    public function testDaysBetweenNextDayIsOne(): void
    {
        $epoch = new \DateTimeImmutable('2024-01-01T00:00:00Z');
        $date = new \DateTimeImmutable('2024-01-02T00:00:01Z');
        $this->assertSame(1, Encryption::daysBetween($epoch, $date));
    }

    public function testDaysBetweenBeforeEpochIsNegative(): void
    {
        $epoch = new \DateTimeImmutable('2024-01-01T00:00:00Z');
        $date = new \DateTimeImmutable('2023-12-31T00:00:00Z');
        $this->assertSame(-1, Encryption::daysBetween($epoch, $date));
    }

    public function testSecondsBetweenPositive(): void
    {
        $epoch = new \DateTimeImmutable('2024-01-01T00:00:00Z');
        $date = new \DateTimeImmutable('2024-01-01T00:01:30Z');
        $this->assertSame(90, Encryption::secondsBetween($epoch, $date));
    }

    public function testSecondsBetweenNegative(): void
    {
        $epoch = new \DateTimeImmutable('2024-01-01T00:01:00Z');
        $date = new \DateTimeImmutable('2024-01-01T00:00:00Z');
        $this->assertSame(-60, Encryption::secondsBetween($epoch, $date));
    }

    public function testEncryptDateRequiresUtc(): void
    {
        $this->requireCredsAndFixture();
        $plain = new \DateTimeImmutable('2024-01-01T00:00:00', new \DateTimeZone('America/Los_Angeles'));

        $this->expectException(\InvalidArgumentException::class);
        \Ubiq\encryptDate(self::$creds, $plain, 'date_2keys');
    }

    public function testEncryptDateRoundTrip(): void
    {
        $this->requireCredsAndFixture();
        $rows = $this->sampleByDataType(self::FIXTURE_PATH, ['date_2keys'], self::ROW_SAMPLE);
        $this->assertNotEmpty($rows, 'No date_2keys rows in fixture');

        foreach ($rows as $row) {
            $expectedPlain = new \DateTimeImmutable($row['plaintext']);
            $expectedCipher = new \DateTimeImmutable($row['ciphertext']);

            $actualCipher = \Ubiq\encryptDate(self::$creds, $expectedPlain, $row['dataset']);
            $this->assertSame(
                $expectedCipher->format('Y-m-d'),
                $actualCipher->format('Y-m-d'),
                "encryptDate mismatch on dataset '" . $row['dataset']
                . "' for plaintext " . $row['plaintext']
            );

            $actualPlain = \Ubiq\decryptDate(self::$creds, $expectedCipher, $row['dataset']);
            $this->assertSame(
                $expectedPlain->format('Y-m-d'),
                $actualPlain->format('Y-m-d'),
                "decryptDate mismatch on dataset '" . $row['dataset']
                . "' for ciphertext " . $row['ciphertext']
            );
        }
    }

    public function testEncryptDateForSearchReturnsArrayOfDates(): void
    {
        $this->requireCredsAndFixture();
        $rows = $this->sampleByDataType(self::FIXTURE_PATH, ['date_2keys'], 1);
        $this->assertNotEmpty($rows);
        $plain = new \DateTimeImmutable($rows[0]['plaintext']);

        $results = \Ubiq\encryptDateForSearch(self::$creds, $plain, $rows[0]['dataset']);

        $this->assertIsArray($results);
        $this->assertNotEmpty($results, 'expected at least one key rotation');
        foreach ($results as $cipher) {
            $this->assertInstanceOf(\DateTimeImmutable::class, $cipher);
            $back = \Ubiq\decryptDate(self::$creds, $cipher, $rows[0]['dataset']);
            $this->assertSame($plain->format('Y-m-d'), $back->format('Y-m-d'));
        }
    }

    public function testEncryptDateTimeForSearchReturnsArrayOfDateTimes(): void
    {
        $this->requireCredsAndFixture();
        $rows = $this->sampleByDataType(self::FIXTURE_PATH, ['datetime'], 1);
        $this->assertNotEmpty($rows);
        $plain = new \DateTimeImmutable($rows[0]['plaintext']);

        $results = \Ubiq\encryptDateTimeForSearch(self::$creds, $plain, $rows[0]['dataset']);

        $this->assertIsArray($results);
        $this->assertNotEmpty($results, 'expected at least one key rotation');
        foreach ($results as $cipher) {
            $this->assertInstanceOf(\DateTimeImmutable::class, $cipher);
            $back = \Ubiq\decryptDateTime(self::$creds, $cipher, $rows[0]['dataset']);
            $this->assertEquals($plain->getTimestamp(), $back->getTimestamp());
        }
    }

    public function testEncryptDateTimeRoundTrip(): void
    {
        $this->requireCredsAndFixture();
        $rows = $this->sampleByDataType(self::FIXTURE_PATH, ['datetime'], self::ROW_SAMPLE);
        $this->assertNotEmpty($rows, 'No datetime rows in fixture');

        foreach ($rows as $row) {
            $expectedPlain = new \DateTimeImmutable($row['plaintext']);
            $expectedCipher = new \DateTimeImmutable($row['ciphertext']);

            $actualCipher = \Ubiq\encryptDateTime(self::$creds, $expectedPlain, $row['dataset']);
            $this->assertEquals(
                $expectedCipher->getTimestamp(),
                $actualCipher->getTimestamp(),
                "encryptDateTime mismatch on dataset '" . $row['dataset']
                . "' for plaintext " . $row['plaintext']
            );

            $actualPlain = \Ubiq\decryptDateTime(self::$creds, $expectedCipher, $row['dataset']);
            $this->assertEquals(
                $expectedPlain->getTimestamp(),
                $actualPlain->getTimestamp(),
                "decryptDateTime mismatch on dataset '" . $row['dataset']
                . "' for ciphertext " . $row['ciphertext']
            );
        }
    }

    /**
     * @param string[] $datasetNames
     * @return array<int, array{ciphertext: string, plaintext: string, dataset: string}>
     */
    private function sampleByDataType(string $path, array $datasetNames, int $limit): array
    {
        $raw = json_decode(file_get_contents($path), true);
        if (!is_array($raw)) {
            $this->fail('Could not decode fixture at ' . $path);
        }
        $want = array_flip($datasetNames);
        $out = [];
        foreach ($raw as $row) {
            if (isset($want[$row['dataset']])) {
                $out[] = $row;
                if (count($out) >= $limit) {
                    break;
                }
            }
        }
        return $out;
    }
}
