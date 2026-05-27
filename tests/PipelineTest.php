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
use Ubiq\Pipeline\EncodeInputOperation;
use Ubiq\Pipeline\DecodeInputOperation;
use Ubiq\Pipeline\PadInputOperation;

/**
 * Unit tests for the input-encoding and input-padding pipeline
 * operations. These exercise pure functions only — no credentials or
 * backend calls required.
 *
 * @covers Ubiq\Pipeline\EncodeInputOperation
 * @covers Ubiq\Pipeline\DecodeInputOperation
 * @covers Ubiq\Pipeline\PadInputOperation
 *
 * @uses Ubiq\Dataset
 */
final class PipelineTest extends TestCase
{
    private function makeDataset(array $config): Dataset
    {
        return new Dataset('test', null, null, $config);
    }

    public function testEncodeNoopWhenInputEncodingMissing(): void
    {
        $dataset = $this->makeDataset([]);
        $this->assertSame('hello', EncodeInputOperation::apply('hello', $dataset));
    }

    public function testEncodeNoopWhenInputEncodingEmpty(): void
    {
        $dataset = $this->makeDataset(['input_encoding' => '']);
        $this->assertSame('hello', EncodeInputOperation::apply('hello', $dataset));
    }

    public function testEncodeBase64RoundTrip(): void
    {
        $dataset = $this->makeDataset(['input_encoding' => 'base64']);
        $encoded = EncodeInputOperation::apply('hello', $dataset);
        $this->assertSame('aGVsbG8=', $encoded);
        $this->assertSame('hello', DecodeInputOperation::apply($encoded, $dataset));
    }

    public function testEncodeBase32RoundTrip(): void
    {
        $dataset = $this->makeDataset(['input_encoding' => 'base32']);
        $encoded = EncodeInputOperation::apply('hello', $dataset);
        // RFC 4648 base32 of "hello" is NBSWY3DP
        $this->assertSame('NBSWY3DP', $encoded);
        $this->assertSame('hello', DecodeInputOperation::apply($encoded, $dataset));
    }

    public function testEncodeRejectsUnknownEncoding(): void
    {
        $dataset = $this->makeDataset(['input_encoding' => 'base42']);
        $this->expectException(\RuntimeException::class);
        EncodeInputOperation::apply('hello', $dataset);
    }

    public function testPadNoopWhenPadCharMissing(): void
    {
        $dataset = $this->makeDataset(['min_input_length' => 8]);
        $this->assertSame('hello', PadInputOperation::apply('hello', $dataset));
    }

    public function testPadLeftPadsToMinLength(): void
    {
        $dataset = $this->makeDataset([
            'input_pad_character' => ' ',
            'min_input_length' => 8,
        ]);
        $this->assertSame('   hello', PadInputOperation::apply('hello', $dataset));
    }

    public function testPadNoopWhenAlreadyAtMinLength(): void
    {
        $dataset = $this->makeDataset([
            'input_pad_character' => ' ',
            'min_input_length' => 5,
        ]);
        $this->assertSame('hello', PadInputOperation::apply('hello', $dataset));
    }

    public function testPadRejectsInputContainingPadCharacter(): void
    {
        $dataset = $this->makeDataset([
            'input_pad_character' => 'x',
            'min_input_length' => 8,
        ]);
        $this->expectException(\RuntimeException::class);
        PadInputOperation::apply('hexlo', $dataset);
    }

    public function testPadUnapplyStripsLeadingPadChars(): void
    {
        $dataset = $this->makeDataset(['input_pad_character' => ' ']);
        $this->assertSame('hello', PadInputOperation::unapply('   hello', $dataset));
    }

    public function testPadUnapplyOnlyStripsLeading(): void
    {
        // Only the leading run is stripped — interior pad chars stay.
        // (In practice the input alphabet excludes the pad char so this
        // shouldn't happen, but we don't want to silently rewrite the
        // middle of a value either.)
        $dataset = $this->makeDataset(['input_pad_character' => ' ']);
        $this->assertSame('he llo', PadInputOperation::unapply(' he llo', $dataset));
    }

    public function testPadUnapplyNoopWhenPadCharMissing(): void
    {
        $dataset = $this->makeDataset([]);
        $this->assertSame('   hello', PadInputOperation::unapply('   hello', $dataset));
    }
}
