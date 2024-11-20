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

/**
 * Implementation of FF1
 * Implementation of FF-1 algorithm per
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */

use \phpseclib3\Math\BigInteger;

class FF1
{
    const BLOCK_SIZE = 16;

    public $radix = 0;
    public $txtmin = 0;
    public $txtmax = 65536;
    public $twkmin = 0;
    public $twkmax = 0;
    public $tweak = [];
    public $alphabet = null;
    public $key = null;

    private static ?BigInteger $big_zero = null;
    private static ?BigInteger $big_one = null;
    
    private static ?Credentials $_creds = null;

    private static function xorArray(&$array1, $offset1, &$array2, $offset2, &$result, $result_offset, $length) {
        // XOR operation for byte arrays
        for ($i = 0; $i < $length; $i++) {
            $result[$result_offset + $i] = ($array1[$offset1 + $i] ^ $array2[$offset2 + $i]) & 0xFF;
        }
    }

    private static function bigIntegerToStringWithAlphabet($number, $desired_string_length, $alphabet) {
        return self::bigIntegerToString($number, strlen($alphabet), $alphabet, $desired_string_length);
    }

    private static function bigIntegerToString($number, $radix, $alphabet, $desired_string_length = FALSE) {
        $result = '';
        $big_radix = new BigInteger($radix);
        $cvt = new BigInteger($number);
        $alphabet_chars = str_split($alphabet);
    
        // Convert the number to the desired base
        while ($cvt->compare(self::$big_zero) > 0) {
            // Calculate the remainder and add the corresponding character to the result
            list($cvt, $remainder) = $cvt->divide($big_radix);
            $remainder = (int)$remainder->toString();
            $result = $alphabet_chars[$remainder] . $result;
        }
    
        if ($desired_string_length !== FALSE) {
            // Check if the length exceeds the desired string length
            if (strlen($result) > $desired_string_length) {
                throw new \Exception("Unable to convert big integer into {$desired_string_length} characters");
            }
        
            // Pad the string with leading "zero characters" to reach the desired size
            if (strlen($result) < $desired_string_length) {
                $padding = str_repeat($alphabet_chars[0], $desired_string_length - strlen($result));
                $result = $padding . $result;
            }
        }
    
        return $result;
    }

    private static function parseBigIntegerFromAlphabet($number_string, $alphabet) : BigInteger {
        return self::parseBigInteger($number_string, strlen($alphabet), $alphabet);
    }

    private static function parseBigInteger($number_string, $radix, $alphabet) : BigInteger {
        // Initialize number to 0 and digit to 1
        $number = new BigInteger(0);
        $digit = new BigInteger(1);
        $big_radix = new BigInteger($radix);
        $alphabet_array = array_flip(str_split($alphabet));
    
        // Iterate over the string in reverse order
        for ($i = strlen($number_string) - 1; $i >= 0; $i--) {
            $character = $number_string[$i];
            $alphabet_idx = $alphabet_array[$character] ?? false;
            if ($alphabet_idx === false) {
                throw new \Exception("Invalid character in number string: " . $character . ' in alphabet ' . $alphabet);
            }
    
            // Update number and digit
            $number = $number->add($digit->multiply(new BigInteger($alphabet_idx)));
            $digit = $digit->multiply($big_radix);
        }
    
        return $number;
    }

    private static function padToBlockSize($data, $block_size, $pad_character = "\0")
    {
        if (sizeof($data) >= $block_size) {
            return $data;
        }

        $padSize = $block_size - (sizeof($data) % $block_size);

        $nullBytes = array_fill(0, $padSize, $pad_character);
    
        return array_merge($nullBytes, $data);
    }

    public function decryptToOutput($ciphertext, Dataset $dataset, $key_number)
    {
        $ciphertext = self::decodeKeyNumber($ciphertext, $dataset, TRUE);

        $plaintext = $this->decrypt($ciphertext);

        return $plaintext;

        // $converted_text = self::bigIntegerToStringWithAlphabet(
        //     new BigInteger($plaintext),
        //     strlen($dataset->structured_config['input_character_set']),
        //     $dataset->structured_config['input_character_set'],
        //     strlen($ciphertext)
        // );

        // return $converted_text;
    }
    
    public function encryptToOutput($text, Dataset $dataset, $key_number)
    {
        $ciphertext = $this->encrypt($text);

        ubiq_debug(self::$_creds, 'Structured encrypted plaintext ' . $text . ' to ciphertext ' . $ciphertext);

        $ciphertext = self::encodeKeyNumber($ciphertext, $dataset, $key_number);

        return $ciphertext;
        
        // $converted_text = self::bigIntegerToStringWithAlphabet(
        //     new BigInteger($ciphertext),
        //     $this->radix,
        //     $this->alphabet,
        //     strlen($text)
        // );

        // return $converted_text;
    }

    public static function decodeKeyNumber(&$text, Dataset $dataset, $remove = FALSE)
    {
        // Get the first character from the text
        $char_buf = $text[0];

        // Find the index of the character in the dataset's OutputCharacters
        $encoded_value = strpos($dataset->structured_config['output_character_set'], $char_buf);

        // Calculate the ct_val
        $key_number = $encoded_value >> (int)$dataset->structured_config['msb_encoding_bits'];

        ubiq_debug(self::$_creds, 'Structured encrypted decoded key number ' . $key_number . ' in ' . $text . ' as ' . $text);

        if ($remove) {
            $encoded_value -= $key_number << (int)$dataset->structured_config['msb_encoding_bits'];
            $ch = $dataset->structured_config['output_character_set'][$encoded_value];

            $text[0] = $ch;

            ubiq_debug(self::$_creds, 'Structured encrypted removed decoded key number to ' . $text);

        }

        return $key_number;
    }

    public static function encodeKeyNumber($text, Dataset $dataset, $key_number)
    {
        // Get the first character from the text
        $char_buf = $text[0];

        // Find the index of the character in the dataset's OutputCharacters
        $ct_val = strpos($dataset->structured_config['output_character_set'], $char_buf);

        // Calculate the ct_val
        $ct_val += $key_number << (int)$dataset->structured_config['msb_encoding_bits'];

        // Get the character from OutputCharacters at the ct_val index
        $ch = $dataset->structured_config['output_character_set'][$ct_val];

        // Replace the character in the text
        $encoded_text = $text;
        $encoded_text[0] = $ch;

        ubiq_debug(self::$_creds, 'Structured encrypted encoded key number ' . $key_number . ' in ' . $text . ' as ' . $encoded_text);

        return $encoded_text;
    }

    public function __construct(Credentials $creds, $key, $alphabet) {
        self::$big_one = new BigInteger(1);
        self::$big_zero = new BigInteger(0);

        if (!empty($alphabet)) {
            $radix = strlen($alphabet);
        }
        self::$_creds = $creds;
        
        $this->key = $key;
        $this->radix = $radix;
        $this->alphabet = $alphabet;
        
        // FF1 and FF3-1 support a radix up to 65536, but the
        // implementation becomes increasingly difficult and
        // less useful in practice after the limits below.
        if ($radix < 2 || $radix > strlen($alphabet))
        {
            throw new \Exception('Invalid radix length');
        }

        // for ff1 : radix**minlen >= 1000000
        // therefore:
        //   minlen = ceil(log_radix(1000000))
        //          = ceil(log_10(1000000) / log_10(radix))
        //          = ceil(6 / log_10(radix))
        $txtmin = ceil(6.0 / log10($radix));
        if ($txtmin < 2 || $txtmin > $this->txtmax) {
            throw new \Exception('Minimum text length out of range');
        }
    }


    private function prf($key, &$src, $src_offset, &$dest, $dest_offset, $length = self::BLOCK_SIZE)
    {
        // IV is 16 bytes of zero
        $iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // #TODO this shouldn't be necessary, should it? 
        // key should be 32 bytes, but it won't work unless its the same as the block size
        $key = str_pad($key, 32, '0');
        $key = substr($key, 0, 16);

        // OpenSSL encryption using AES-128-CBC with no padding
        $src_length = sizeof($src) - $src_offset;

        for ($i = 0; $i < $length && $i < $src_length; $i += self::BLOCK_SIZE) {
            // Pad src_part to match the block size of self::BLOCK_SIZE bytes if necessary
            $src_part = array_slice($src, $src_offset, self::BLOCK_SIZE);
            $src_part = self::padToBlockSize($src_part, self::BLOCK_SIZE);

            $encrypted = openssl_encrypt(
                implode(array_map("chr", $src_part)),
                'aes-128-cbc',
                $key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
                implode(array_map("chr", $iv)),
            );
            
            if (!empty(openssl_error_string())) {
                ubiq_debug(self::$_creds, 'Structured encrypted OpenSSL error ' . openssl_error_string());
            }

            $encrypted_arr = array_values(unpack('C*', $encrypted));

            // Adjust the destination buffer with the result
            array_splice($dest, $dest_offset, sizeof($encrypted_arr), $encrypted_arr);
        }

        return $dest;
    }

    public function encrypt(string $x) {
        return $this->cipher($x, [], TRUE);
    }

    public function decrypt(string $x) {
        return $this->cipher($x, [], FALSE);
    }
    /*
    * The comments below reference the steps of the algorithm described here:
    *
    * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
    */
    private function cipher(string $x, array $twk, bool $encrypt) {
        $radix = $this->radix;
        $txtmin = $this->txtmin;
        $txtmax = $this->txtmax;
        $twkmin = $this->twkmin;
        $twkmax = $this->twkmax;
        $alphabet = $this->alphabet;
        $tweak = $this->tweak;
        $key = $this->key;
        $big_radix = new BigInteger($radix);

        $n = strlen($x);
        $u = intdiv($n, 2);
        $v = $n - $u;
    
        // Step 3, 4
        $a = intval(ceil((log($radix) / log(2)) * $v)) + 7;
        $b = intval($a / 8);
        $d = (4 * (($b + 3) / 4)) + 4;
    
        $p = 16;
        $r = (($d + 15) / 16) * 16;
    
        $A = "";
        $B = "";
        $PQ = [];
        $R = [];
        $q = 0;
    
        // Check tweak if none is supplied
        if ($n < $txtmin || $n > $txtmax) {
            throw new \Exception("Invalid input length");
        } elseif (sizeof($tweak) < $twkmin || ($twkmax > 0 && sizeof($tweak) > $twkmax)) {
            throw new \Exception("Invalid tweak length");
        }

        // The number of bytes in q
        $q = intval((sizeof($tweak) + $b + 1 + 15) / 16) * 16;
        
        // P and Q need to be adjacent in memory for encryption
        $PQ = array_fill(0, $p + $q, "\0");
        $R = array_fill(0, $r, "\0");
    
        // Step 2
        if ($encrypt) {
            $A = substr($x, 0, $u);
            $B = substr($x, $u);
        } else {
            $B = substr($x, 0, $u);
            $A = substr($x, $u);
        }
    
        // Step 5
        $PQ[0] = 1 & 0xFF;
        $PQ[1] = 2 & 0xFF;
        $PQ[2] = 1 & 0xFF;
        $PQ[3] = ($radix >> 16) & 0xFF;
        $PQ[4] = ($radix >> 8) & 0xFF;
        $PQ[5] = ($radix >> 0) & 0xFF;
        $PQ[6] = 10 & 0xFF;
        $PQ[7] = $u & 0xFF;
        $PQ[8] = ($n >> 24) & 0xFF;
        $PQ[9] = ($n >> 16) & 0xFF;
        $PQ[10] = ($n >> 8) & 0xFF;
        $PQ[11] = ($n >> 0) & 0xFF;
        $PQ[12] = (sizeof($tweak) >> 24) & 0xFF;
        $PQ[13] = (sizeof($tweak) >> 16) & 0xFF;
        $PQ[14] = (sizeof($tweak) >> 8) & 0xFF;
        $PQ[15] = (sizeof($tweak) >> 0) & 0xFF;
    
        // Step 6i, the static parts
        
        // if we allow tweaks, do this here
        // Array.Copy(tweak, 0, PQ, p, tweak.Length);
        
        for ($i = 0; $i < 10; $i++) {
            // Step 6v
            $m = (($i + ($encrypt ? 1 : 0)) % 2 == 1) ? $u : $v;
    
            $big_radix_pow_m = $big_radix->pow(new BigInteger($m));

            $c = 0;
            $y = 0;
            $numb = [];
    
            // Step 6i, the non-static parts
            $PQ[sizeof($PQ) - $b - 1] = ($encrypt ? $i : (9 - $i)) & 0xFF;
    
            // convert numeral string B to an integer
            // export that integer as a byte array in to q
            $c = self::parseBigIntegerFromAlphabet($B, $alphabet);

            // assume this is big-endian order because it came from the string
            $numb = array_values(unpack('C*', $c->toBytes()));
    
            if ($numb[0] == 0 && sizeof($numb) > 1) {
                // Remove the extra byte if it exists
                array_shift($numb);
            }

            if ($b <= sizeof($numb)) {
                array_splice($PQ, sizeof($PQ) - $b, $b, array_slice($numb, 0, $b));
            } else {
                // Left pad with zeros
                $PQ = self::padToBlockSize($PQ, sizeof($PQ) + $b - sizeof($numb), 0 & 0xFF);
                array_splice($PQ, sizeof($PQ) - sizeof($numb), sizeof($numb), array_slice($numb, 0, sizeof($numb)));
            }

            // Step 6ii - perform encryption
            self::prf($key, $PQ, 0, $R, 0, sizeof($PQ));
    
            // Step 6iii - fill subsequent blocks
            // with the result of ciph(R ^ 1), ciph(R ^ 2), ...
            for ($j = 1; $j < $r / 16; $j++) {
                $l = $j * 16;

                $R[$l + 0] = 0 & 0xFF;
                $R[$l + 1] = 0 & 0xFF;
                $R[$l + 2] = 0 & 0xFF;
                $R[$l + 3] = 0 & 0xFF;
                $R[$l + 4] = 0 & 0xFF;
                $R[$l + 5] = 0 & 0xFF;
                $R[$l + 6] = 0 & 0xFF;
                $R[$l + 7] = 0 & 0xFF;
                $R[$l + 8] = 0 & 0xFF;
                $R[$l + 9] = 0 & 0xFF;
                $R[$l + 10] = 0 & 0xFF;
                $R[$l + 11] = 0 & 0xFF;
                $R[$l + 12] = ($j >> 24) & 0xFF;
                $R[$l + 13] = ($j >> 16) & 0xFF;
                $R[$l + 14] = ($j >> 8) & 0xFF;
                $R[$l + 15] = ($j >> 0) & 0xFF;
    
                self::xorArray($R, $l, $R, 0, $R, $l, self::BLOCK_SIZE);
    
                self::prf($key, $R, $l, $R, $l);
            }
    
            // Step 6vi
            // calculate A +/- y mod radix**m
            // where y is the number formed by the first d bytes of R
            // reverse array, back into little-endian order
            $yA = array_reverse(array_slice($R, 0, $d));
            
            $y = new BigInteger(implode("", $yA));
            $y = $y->modPow(self::$big_one, self::$big_one->bitwise_leftShift(8 * $d));
    
            $c = self::parseBigInteger($A, $radix, $alphabet);
    
            if ($encrypt) {
                $c = $c->add($y);
            } else {
                $c = $c->subtract($y);
            }

            $c = $c->modPow(self::$big_one, $big_radix_pow_m);
    
            // Step 6viii
            $A = $B;
    
            // Step 6ix
            $B = self::bigIntegerToString($c, $radix, $alphabet);
        }
    
        // Step 7
        return $encrypt ? ($A . $B) : ($B . $A);
    }

}    