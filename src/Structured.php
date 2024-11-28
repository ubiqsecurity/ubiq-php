<?php

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

class Structured {
    const ENCRYPTION_RULE_TYPE_PREFIX = 'prefix';
    const ENCRYPTION_RULE_TYPE_SUFFIX = 'suffix';
    const ENCRYPTION_RULE_TYPE_PASSTHROUGH = 'passthrough';

    public static function deconstructFromPartialRules(string $string, Credentials $creds, Dataset $dataset)
    {
        ubiq_debug($creds, 'Starting deconstructFromPartialRules for ' . $string, 2);

        $prefix_str = '';
        $suffix_str = '';
        $passthrough_processed = false;
        $passthrough_vals = mb_str_split($dataset->structured_config['passthrough']);
        $passthrough_chars = array_flip($passthrough_vals);

        foreach ($dataset->structured_config['passthrough_rules'] as $action) {
            if ($action['type'] === Structured::ENCRYPTION_RULE_TYPE_PASSTHROUGH) {
                $passthrough_processed = true;
                $mask_str = $string;
                $string = str_replace($passthrough_vals, '', $string);
    
                ubiq_debug($creds, 'Parsing for partial encryption remove passthrough chars to result in ' . $string, 2);
            } elseif ($action['type'] === Structured::ENCRYPTION_RULE_TYPE_PREFIX) {
                $prefix_str = mb_substr($string, 0, $action['value']);
                $string = mb_substr($string, $action['value']);

                ubiq_debug($creds, 'Parsing for partial encryption prefix ' . $prefix_str . ' and remainder ' . $string, 2);
            } elseif ($action['type'] === Structured::ENCRYPTION_RULE_TYPE_SUFFIX) {
                $suffix_str = mb_substr($string, -$action['value']);
                $string = mb_substr($string, 0, mb_strlen($string)-$action['value']);

                ubiq_debug($creds, 'Parsing for partial encryption suffix ' . $suffix_str . ' and remainder ' . $string, 2);
            }
        }

        if (!$passthrough_processed && !empty($passthrough_chars)) {
            $mask_str = $string;
            $string = str_replace($passthrough_vals, '', $string);

            ubiq_debug($creds, 'Parsing for partial encryption remove passthrough chars to result in ' . $string, 2);
        }

        ubiq_debug($creds, 'Finished deconstructFromPartialRules to ' . $string, 2);

        return [
            'mask' => $mask_str ?? '',
            'string' => $string,
            'prefix' => $prefix_str,
            'suffix' => $suffix_str
        ];
    }

    public static function strMask($string, $masked_str, $mask_chars)
    {
        $formatted_str = '';
        $k = 0;
        $mask_str_array = mb_str_split($masked_str);
        $cipher_str_array = mb_str_split($string);

        for ($i = 0; $i < sizeof($mask_str_array); $i++) {
            if (!array_key_exists($mask_str_array[$i], $mask_chars)) {
                $formatted_str .= $cipher_str_array[$k];
                $k++;
            }
            else {
                $formatted_str .= $mask_str_array[$i];
            }
        }

        return $formatted_str;
    }

    
    public static function reconstructFromPartialRules(string $string, array $deconstruct_parts, Credentials $creds, Dataset $dataset)
    {
        ubiq_debug($creds, 'Starting reconstructFromPartialRules for ' . $string, 2);
       
        $passthrough_processed = false;
        $passthrough_vals = mb_str_split($dataset->structured_config['passthrough']);
        $passthrough_chars = array_flip($passthrough_vals);

        // reconstruct in the reverse order
        $rules = array_reverse($dataset->structured_config['passthrough_rules']);
        foreach ($rules as $action) {
            if ($action['type'] === Structured::ENCRYPTION_RULE_TYPE_PASSTHROUGH) {
                $passthrough_processed = true;
                
                $string = self::strMask($string, $deconstruct_parts['mask'], $passthrough_chars);

                ubiq_debug($creds, 'Reconstructing for partial encryption add passthrough chars to result in ' . $string, 2);
            } elseif ($action['type'] === Structured::ENCRYPTION_RULE_TYPE_PREFIX) {
                $string = $deconstruct_parts['prefix'] . $string;

                ubiq_debug($creds, 'Reconstructing for partial encryption prefix ' . $deconstruct_parts['prefix'] . ' to ' . $string, 2);
            } elseif ($action['type'] === Structured::ENCRYPTION_RULE_TYPE_SUFFIX) {
                $string = $string . $deconstruct_parts['suffix'];

                ubiq_debug($creds, 'Reconstructing for partial encryption suffix ' . $deconstruct_parts['suffix'] . ' to ' . $string, 2);
            }
        }

        if (!$passthrough_processed && !empty($passthrough_chars)) {
            $string = self::strMask($string, $deconstruct_parts['mask'], $passthrough_chars);

            ubiq_debug($creds, 'Parsing for partial encryption add passthrough chars to result in ' . $string, 2);
        }

        ubiq_debug($creds, 'Finished reconstructFromPartialRules to ' . $string, 2);

        return $string;
    }

}