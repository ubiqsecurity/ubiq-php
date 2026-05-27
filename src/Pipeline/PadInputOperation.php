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
 * Pre-encryption transform that left-pads the input with
 * input_pad_character up to min_input_length so the value matches the
 * FF1 length constraint. Reverse direction strips the leading pad
 * characters added by the encrypt-side apply().
 *
 * Mirrors com.ubiqsecurity.pipeline.operations.PadInputOperation (Java)
 * and UbiqSecurity.Internals.Structured.Pipeline.Operations
 * .PadInputOperation (.NET).
 */
class PadInputOperation
{
    /**
     * Left-pad the encrypt-side input up to min_input_length.
     *
     * @param string  $value   The (possibly encoded) plaintext
     * @param Dataset $dataset The dataset whose structured_config carries the pad config
     *
     * @return string The padded value (or $value unchanged when no pad is configured)
     */
    public static function apply(string $value, Dataset $dataset): string
    {
        $padChar = $dataset->structured_config['input_pad_character'] ?? null;

        if ($padChar === null || $padChar === '') {
            return $value;
        }

        if (mb_strpos($value, (string) $padChar) !== false) {
            throw new \RuntimeException(
                "Input string already includes the padding character: '" . $padChar . "'"
            );
        }

        $minLength = (int) ($dataset->structured_config['min_input_length'] ?? 0);
        return self::padLeft($value, $padChar, $minLength);
    }

    /**
     * Strip the leading pad characters that {@see apply()} added.
     *
     * Only used by the decrypt path. We don't attempt to "know" how
     * many pad chars to strip — we trust the pad character is not
     * legal in the original input alphabet and strip every leading
     * occurrence.
     *
     * @param string  $value   The FF1-decrypted value
     * @param Dataset $dataset The dataset whose structured_config carries the pad config
     */
    public static function unapply(string $value, Dataset $dataset): string
    {
        $padChar = $dataset->structured_config['input_pad_character'] ?? null;

        if ($padChar === null || $padChar === '') {
            return $value;
        }

        $len = mb_strlen($value);
        $i = 0;
        while ($i < $len && mb_substr($value, $i, 1) === (string) $padChar) {
            $i++;
        }
        return mb_substr($value, $i);
    }

    private static function padLeft(string $value, string $padChar, int $minLength): string
    {
        $deficit = $minLength - mb_strlen($value);
        if ($deficit <= 0) {
            return $value;
        }
        return str_repeat((string) $padChar, $deficit) . $value;
    }
}
