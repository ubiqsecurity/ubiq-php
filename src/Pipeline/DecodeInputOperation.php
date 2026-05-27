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
 * Post-decryption transform that decodes the FF1 output according to
 * the dataset's input_encoding setting. Reverse of
 * {@see EncodeInputOperation}.
 */
class DecodeInputOperation
{
    /**
     * Apply the decoding transform.
     *
     * @param string  $value   The post-FF1 plaintext to decode
     * @param Dataset $dataset The dataset whose structured_config carries input_encoding
     *
     * @return string The decoded value (or $value unchanged when no encoding is set)
     */
    public static function apply(string $value, Dataset $dataset): string
    {
        $encoding = $dataset->structured_config['input_encoding'] ?? null;

        if ($encoding === null || trim((string) $encoding) === '') {
            return $value;
        }

        if ($encoding === 'base64') {
            $decoded = base64_decode($value, true);
            if ($decoded === false) {
                throw new \RuntimeException('Failed to base64-decode decrypted value');
            }
            return $decoded;
        }

        if ($encoding === 'base32') {
            return self::base32decode($value);
        }

        throw new \RuntimeException(
            "input_encoding value '" . $encoding . "' is not currently supported"
        );
    }

    /**
     * RFC 4648 base32 decoder. Mirrors Guava BaseEncoding.base32().
     */
    private static function base32decode(string $value): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $alphabetMap = array_flip(str_split($alphabet));
        $value = rtrim($value, '=');
        $binary = '';

        foreach (str_split($value) as $char) {
            if (!isset($alphabetMap[$char])) {
                throw new \RuntimeException('Invalid base32 character: ' . $char);
            }
            $binary .= str_pad(decbin($alphabetMap[$char]), 5, '0', STR_PAD_LEFT);
        }

        $decoded = '';
        for ($i = 0; $i + 8 <= strlen($binary); $i += 8) {
            $decoded .= chr(bindec(substr($binary, $i, 8)));
        }

        return $decoded;
    }
}
