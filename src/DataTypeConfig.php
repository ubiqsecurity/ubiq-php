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

namespace Ubiq;

/**
 * Typed wrapper for the data_type_config block on a structured dataset.
 *
 * Mirrors com.ubiqsecurity.DataTypeConfig (Java) and
 * UbiqSecurity.Internals.WebService.Models.DataTypeConfig (.NET).
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class DataTypeConfig
{
    /** Integer-bit-width for integer datasets (32 or 64). */
    public ?int $size = null;

    /** Inclusive lower bound for integer datasets. */
    public ?int $minInputIntValue = null;

    /** Inclusive upper bound for integer datasets. */
    public ?int $maxInputIntValue = null;

    /**
     * Epoch reference date for date / datetime datasets. ISO 8601
     * string preserved as-is from the server; convertible to a
     * \DateTimeImmutable via {@see epochAsDateTime()}.
     */
    public ?string $epoch = null;

    /** Inclusive lower bound for date / datetime datasets (ISO 8601 string). */
    public ?string $minInputDateValue = null;

    /** Inclusive upper bound for date / datetime datasets (ISO 8601 string). */
    public ?string $maxInputDateValue = null;

    /**
     * Build a DataTypeConfig from the JSON object returned by the
     * /api/v0/ffs endpoint. Returns null when the input is empty or
     * not an array.
     */
    public static function fromArray($raw): ?DataTypeConfig
    {
        if (empty($raw) || !is_array($raw)) {
            return null;
        }

        $cfg = new DataTypeConfig();
        if (isset($raw['size'])) {
            $cfg->size = (int) $raw['size'];
        }
        if (isset($raw['min_input_int_value'])) {
            $cfg->minInputIntValue = (int) $raw['min_input_int_value'];
        }
        if (isset($raw['max_input_int_value'])) {
            $cfg->maxInputIntValue = (int) $raw['max_input_int_value'];
        }
        if (isset($raw['epoch'])) {
            $cfg->epoch = (string) $raw['epoch'];
        }
        if (isset($raw['min_input_date_value'])) {
            $cfg->minInputDateValue = (string) $raw['min_input_date_value'];
        }
        if (isset($raw['max_input_date_value'])) {
            $cfg->maxInputDateValue = (string) $raw['max_input_date_value'];
        }
        return $cfg;
    }

    public function epochAsDateTime(): ?\DateTimeImmutable
    {
        return self::parseUtc($this->epoch);
    }

    public function minInputDateAsDateTime(): ?\DateTimeImmutable
    {
        return self::parseUtc($this->minInputDateValue);
    }

    public function maxInputDateAsDateTime(): ?\DateTimeImmutable
    {
        return self::parseUtc($this->maxInputDateValue);
    }

    private static function parseUtc(?string $value): ?\DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }
        $dt = new \DateTimeImmutable($value);
        return $dt->setTimezone(new \DateTimeZone('UTC'));
    }
}
