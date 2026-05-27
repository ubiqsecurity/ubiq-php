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

namespace Ubiq\Pipeline;

use Ubiq\Dataset;

/**
 * Pre-encryption transform that encodes the input according to the
 * dataset's input_encoding setting (base64 or base32). When
 * input_encoding is null/empty this is a no-op.
 *
 * Mirrors com.ubiqsecurity.pipeline.operations.EncodeInputOperation
 * (Java) and UbiqSecurity.Internals.Structured.Pipeline.Operations
 * .EncodeInputOperation (.NET).
 */
class EncodeInputOperation
{
    /**
     * Apply the encoding transform.
     *
     * @param string  $value   The plaintext (post-passthrough-deconstruct) to encode
     * @param Dataset $dataset The dataset whose structured_config carries input_encoding
     *
     * @return string The encoded value (or $value unchanged when no encoding is set)
     */
    public static function apply(string $value, Dataset $dataset): string
    {
        $encoding = $dataset->structured_config['input_encoding'] ?? null;

        if ($encoding === null || trim((string) $encoding) === '') {
            return $value;
        }

        if ($encoding === 'base64') {
            return base64_encode($value);
        }

        if ($encoding === 'base32') {
            return self::base32encode($value);
        }

        throw new \RuntimeException(
            "input_encoding value '" . $encoding . "' is not currently supported"
        );
    }

    /**
     * RFC 4648 base32 encoder. PHP has no built-in base32, so this
     * follows the same alphabet and padding rules as the Java/.NET
     * implementations (Google Guava BaseEncoding.base32).
     */
    private static function base32encode(string $value): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bytes = unpack('C*', $value) ?: [];
        $binary = '';
        foreach ($bytes as $byte) {
            $binary .= str_pad(decbin($byte), 8, '0', STR_PAD_LEFT);
        }

        $padBits = (5 - (strlen($binary) % 5)) % 5;
        $binary .= str_repeat('0', $padBits);

        $encoded = '';
        for ($i = 0; $i < strlen($binary); $i += 5) {
            $chunk = substr($binary, $i, 5);
            $encoded .= $alphabet[bindec($chunk)];
        }

        $padChars = (8 - (strlen($encoded) % 8)) % 8;
        return $encoded . str_repeat('=', $padChars);
    }
}
