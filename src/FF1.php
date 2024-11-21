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
    public $tweak = null;
    public $twkmin = 0;
    public $twkmax = 0;
    public $alphabet = null;
    public $key = null;

    private static ?BigInteger $big_zero = null;
    private static ?BigInteger $big_one = null;
    
    private static ?Credentials $_creds = null;



    
    private static function bytesToBigInteger($array) : BigInteger
    {
        $length = sizeof($array);
        
        $big_256 = new BigInteger(256);
        $pow = new BigInteger(1);
        $result = new BigInteger(0);
        for ($i = 0; $i < sizeof($array); $i++) {
            $result = $result->add($pow->multiply(new BigInteger($array[$length - $i - 1])));
            $pow = $pow->multiply($big_256);
        }
        
        return $result;
    }
    
    private static function xorArray(&$array1, $offset1, &$array2, $offset2, &$result, $result_offset, $length) {
        // XOR operation for byte arrays
        for ($i = 0; $i < $length; $i++) {
            $result[$result_offset + $i] = ($array1[$offset1 + $i] ^ $array2[$offset2 + $i]) & 0xFF;
        }
    }

    private static function bigIntegerToString($number, $alphabet, $desired_string_length = FALSE) {
        $result = '';
        $radix = strlen($alphabet);
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

    private static function stringToBigInteger($number_string, $alphabet) : BigInteger {
        $radix = strlen($alphabet);
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
        $text = self::decodeKeyNumber($ciphertext, $dataset, TRUE);
        ubiq_debugv('text ' . $text);

        // convert to a big number in the output charset radix
        $text = self::stringToBigInteger($text, $dataset->structured_config['output_character_set']);
        ubiq_debugv('text ' . $text->toString());

        // convert to a big number string in the input charset radix
        $text = self::bigIntegerToString($text, $dataset->structured_config['input_character_set'], strlen($ciphertext));
        ubiq_debugv('text ' . $text);

        $text = $this->decrypt($text);
        ubiq_debug(self::$_creds, 'Structured decrypt ciphertext ' . $ciphertext . ' to plaintext ' . $text);

        return $text;
    }
    
    public function encryptToOutput($text, Dataset $dataset, $key_number)
    {
        // encrypt
        $ciphertext = $this->encrypt($text);
        ubiq_debug(self::$_creds, 'Plaintext ' . $text . ' to ciphertext ' . $ciphertext);

        // convert to a big number in the input charset radix
        $ciphertext = self::stringToBigInteger($ciphertext, $dataset->structured_config['input_character_set']);
        ubiq_debugv('ciphertext ' . $ciphertext->toString());

        // convert that to a bignumber string in the output radix
        $ciphertext = self::bigIntegerToString($ciphertext, $dataset->structured_config['output_character_set'], strlen($text));
        ubiq_debugv('ciphertext ' . $ciphertext);

        $ciphertext = self::encodeKeyNumber($ciphertext, $dataset, $key_number);
        ubiq_debugv('ciphertext ' . $ciphertext);

        return $ciphertext;
    }

    public static function decodeKeyNumber($text, Dataset $dataset, $return_text = FALSE)
    {
        // Get the first character from the text
        $char_buf = $text[0];

        // Find the index of the character in the dataset's OutputCharacters
        $encoded_value = strpos($dataset->structured_config['output_character_set'], $char_buf);
        ubiq_debugv('output_character_set ' . $dataset->structured_config['output_character_set']);
        ubiq_debugv('char_buf ' . $char_buf);
        
        // Calculate the ct_val
        $key_number = $encoded_value >> (int)$dataset->structured_config['msb_encoding_bits'];

        ubiq_debug(self::$_creds, 'Decoded key number ' . $key_number . ' in ' . $text . ' as ' . $text);

        if ($return_text) {
            $encoded_value -= $key_number << (int)$dataset->structured_config['msb_encoding_bits'];
            $ch = $dataset->structured_config['output_character_set'][$encoded_value];

            $decoded_text = $text;
            $decoded_text[0] = $ch;

            ubiq_debug(self::$_creds, 'Structured decoded key number ' . $key_number . ' from ' . $text . ' as ' . $decoded_text);

            return $decoded_text;
        }

        return $key_number;
    }

    public static function encodeKeyNumber($text, Dataset $dataset, $key_number)
    {
        // Get the first character from the text
        $char_buf = $text[0];

        // Find the index of the character in the dataset's OutputCharacters
        $ct_val = strpos($dataset->structured_config['output_character_set'], $char_buf);
        ubiq_debugv('output_character_set ' . $dataset->structured_config['output_character_set']);
        ubiq_debugv('char_buf ' . $char_buf);
        ubiq_debugv('ct_val ' . $ct_val);

        // Calculate the ct_val
        $ct_val += $key_number << (int)$dataset->structured_config['msb_encoding_bits'];
        ubiq_debugv('ct_val ' . $ct_val);

        // Get the character from OutputCharacters at the ct_val index
        $ch = $dataset->structured_config['output_character_set'][$ct_val];
        ubiq_debugv('ch ' . $ch);

        // Replace the character in the text
        $encoded_text = $text;
        $encoded_text[0] = $ch;

        ubiq_debug(self::$_creds, 'Encoded key number ' . $key_number . ' in ' . $text . ' as ' . $encoded_text);

        return $encoded_text;
    }

    public function __construct(Credentials $creds, $key, $tweak, $alphabet) {
        self::$big_one = new BigInteger(1);
        self::$big_zero = new BigInteger(0);

        if (!empty($alphabet)) {
            $radix = strlen($alphabet);
        }
        self::$_creds = $creds;
        
        $this->key = $key;
        $this->tweak = $tweak;
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


    private function prf($src, $src_offset, &$dest, $dest_offset, $length = self::BLOCK_SIZE, $it = 0, $enc = TRUE)
    {
        // IV is 16 bytes of zero
        $iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
               
        ubiq_debugv('iv ' .  implode(',', $iv));
        // $iv = implode("", array_map("chr", $iv)); // make sure this is outside the loop
            
        $key = array_values(unpack('C*', $this->key));
        ubiq_debugv('key ' .  implode(',', $key));
        ubiq_debugv('src ' .  implode(',', $src));
        ubiq_debugv('dest ' .  implode(',', $dest));

        // OpenSSL encryption using AES-128-CBC with no padding
        $src_length = sizeof($src) - $src_offset;

        
        $aes = new \phpseclib3\Crypt\AES('cbc');
        $aes->setKey(implode("", array_map("chr", $key)));
        $aes->setIV(implode("", array_map("chr", $iv)));
        $aes->disablePadding();
        $aes->enableContinuousBuffer();

        ubiq_debugv('getEngine ' .  $aes->getEngine());

        for ($i = 0; $i < $length && $i < $src_length; $i += self::BLOCK_SIZE) {
            // Pad src_part to match the block size of self::BLOCK_SIZE bytes if necessary
            $src_part = array_slice($src, $i + $src_offset, self::BLOCK_SIZE);
            $src_part = self::padToBlockSize($src_part, self::BLOCK_SIZE);

            ubiq_debugv('src_part ' .  implode(',', $src_part));

            $encrypted = $aes->encrypt(implode("", array_map("chr", $src_part)));
            
            // known results from node
            // if (($enc && $it == 0) || (!$enc && $it == 9)) {
            //     $encrypted = implode("", array_map("chr", [52,46,140,41,31,31,85,172,194,31,200,204,137,251,44,65]));
            // } elseif (($enc && $it == 1) || (!$enc && $it == 8)) {
            //     $encrypted = implode("", array_map("chr", [83,1,193,142,170,145,143,77,68,48,248,84,5,53,98,187]));
            // } elseif (($enc && $it == 2) || (!$enc && $it == 7)) {
            //     $encrypted = implode("", array_map("chr", [238,239,60,224,204,17,228,122,217,196,106,46,43,185,91,135]));
            // } elseif (($enc && $it == 3) || (!$enc && $it == 6)) {
            //     $encrypted = implode("", array_map("chr", [161,91,255,84,13,65,163,90,26,51,210,45,21,108,149,240]));
            // } elseif (($enc && $it == 4) || (!$enc && $it == 5)) {
            //     $encrypted = implode("", array_map("chr", [212,68,32,20,71,244,233,201,112,42,200,168,55,99,23,139]));
            // } elseif (($enc && $it == 5) || (!$enc && $it == 4)) {
            //     $encrypted = implode("", array_map("chr", [135,60,184,130,58,79,213,180,26,36,255,237,124,146,95,132]));
            // } elseif (($enc && $it == 6) || (!$enc && $it == 3)) {
            //     $encrypted = implode("", array_map("chr", [19,121,148,146,65,230,238,195,5,114,44,160,164,200,203,164]));
            // } elseif (($enc && $it == 7) || (!$enc && $it == 2)) {
            //     $encrypted = implode("", array_map("chr", [61,36,110,203,209,129,98,141,49,141,114,150,70,190,144,219]));
            // } elseif (($enc && $it == 8) || (!$enc && $it == 1)) {
            //     $encrypted = implode("", array_map("chr", [217,205,126,70,16,191,228,243,171,9,70,103,248,177,250,236]));
            // } elseif (($enc && $it == 9) || (!$enc && $it == 0)) {
            //     $encrypted = implode("", array_map("chr", [214,80,49,79,163,188,145,51,63,183,127,236,19,74,68,170]));
            // }

            ubiq_debugv('encrypted phpseclib ' .  implode(',', array_values(unpack('C*', $encrypted))));

            // if using openssl, the IV for subsequent encryption rounds
            // is the encrypted byte array from the previous round
            // phpseclib does with the continuousBuffer setting
            // https://www.php.net/manual/en/function.openssl-encrypt.php
            // https://api.phpseclib.com/1.0/Crypt_AES.html#method_enableContinuousBuffer
            //
            // $encrypted = openssl_encrypt(
            //     implode("", array_map("chr", $src_part)),
            //     'aes-256-cbc',
            //     implode(array_map("chr", $key)),
            //     OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
            //     $iv,
            // );
            // $iv = $encrypted;
            // ubiq_debugv('encrypted openssl ' .  implode(',', array_values(unpack('C*', $encrypted))));

            if (!empty(openssl_error_string())) {
                ubiq_debug(self::$_creds, 'Structured encrypted OpenSSL error ' . openssl_error_string());
            }
        }
        ubiq_debugv('final encrypted ' .  implode(',', array_values(unpack('C*', $encrypted))));

        $encrypted_arr = array_values(unpack('C*', $encrypted));

        // Adjust the destination buffer with the result
        array_splice($dest, $dest_offset, sizeof($encrypted_arr), $encrypted_arr);

        return $dest;
    }

    public function encrypt(string $x) {
        return $this->cipher($x, TRUE);
    }

    public function decrypt(string $x) {
        return $this->cipher($x, FALSE);
    }
    /*
    * The comments below reference the steps of the algorithm described here:
    *
    * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
    */
    private function cipher(string $x, bool $encrypt) {
        $radix = $this->radix;
        $txtmin = $this->txtmin;
        $txtmax = $this->txtmax;
        $twkmin = $this->twkmin;
        $twkmax = $this->twkmax;
        $alphabet = $this->alphabet;
        $key = $this->key;
        $tweak = $this->tweak;

        // tweak comes in as a base64 string
        $tweak = array_values(unpack('C*', base64_decode($tweak)));
        $big_radix = new BigInteger($radix);

        $n = strlen($x);
        $u = floor($n / 2);
        $v = $n - $u;
        
        ubiq_debugv('x ' . $x);
        ubiq_debugv('n ' . $n);
        ubiq_debugv('u ' . $u);
    
        // Step 3, 4
        $a = intval(ceil((log($radix) / log(2)) * $v)) + 7;
        $b = intval($a / 8);
        $d = 4 * intval(($b + 3) / 4) + 4;
    
        $p = 16;
        $r = intval(($d + 15) / 16) * 16;
        ubiq_debugv('r ' . $r);
    
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
        ubiq_debugv('sizeof($tweak) ' . sizeof($tweak));
        ubiq_debugv('q ' . $q);
        
        // P and Q need to be adjacent in memory for encryption
        $PQ = array_fill(0, $p + $q, 0);
        $R = array_fill(0, $r, 0);
    
        ubiq_debugv('R ' . implode(',', $R));
        
        // Step 2
        if ($encrypt) {
            $A = substr($x, 0, $u);
            $B = substr($x, $u);
        } else {
            $B = substr($x, 0, $u);
            $A = substr($x, $u);
        }
        ubiq_debugv('A ' . $A);
        ubiq_debugv('B ' . $B);
        
    
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
    
        array_splice($PQ, $p, sizeof($tweak), $tweak);

        ubiq_debugv('PQ ' . implode(',', $PQ));

        // Step 6i, the static parts
        
        // if we allow tweaks, do this here
        
        for ($i = 0; $i < 10; $i++) {
            // Step 6v
            $m = (($i + ($encrypt ? 1 : 0)) % 2 == 1) ? $u : $v;
            ubiq_debugv('i ' . $i);
            ubiq_debugv('m ' . $m);
    
            $big_radix_pow_m = $big_radix->pow(new BigInteger($m));

            $c = 0;
            $y = 0;
            $numb = [];
            ubiq_debugv('b ' . $b);
            ubiq_debugv('sizeof($PQ) ' . sizeof($PQ));
    
            // Step 6i, the non-static parts
            $PQ[sizeof($PQ) - $b - 1] = ($encrypt ? $i : (9 - $i)) & 0xFF;
            ubiq_debugv('PQ ' . (sizeof($PQ) - $b - 1) . ' ' . (($encrypt ? $i : (9 - $i)) & 0xFF));
    
            // convert numeral string B to an integer
            // export that integer as a byte array in to q
            $c = self::stringToBigInteger($B, $alphabet);
            ubiq_debugv('c ' . $c->toString());

            // assume this is big-endian order because it came from the string
            $numb = array_values(unpack('C*', $c->toBytes()));
            ubiq_debugv('numb ' . implode(',', $numb));
    
            if ($numb[0] == 0 && sizeof($numb) > 1) {
                // Remove the extra byte if it exists
                array_shift($numb);
            }
            
            ubiq_debugv('sizeof($numb) ' . sizeof($numb));

            // Left pad with zeros
            if ($b > sizeof($numb)) {
                ubiq_debugv('adding zeros');
                $numb = self::padToBlockSize($numb, $b, 0);
            }
            array_splice($PQ, sizeof($PQ) - $b, $b, array_slice($numb, 0, $b));
            ubiq_debugv('PQ ' . implode(',', $PQ));

            // Step 6ii - perform encryption
            self::prf($PQ, 0, $R, 0, sizeof($PQ), $i, $encrypt);
    
            // Step 6iii - fill subsequent blocks
            // with the result of ciph(R ^ 1), ciph(R ^ 2), ...
            ubiq_debugv('intval($r / 16) ' . intval($r / 16));
            
            for ($j = 1; $j < intval($r / 16); $j++) {
                $l = $j * 16;

                ubiq_debugv('l ' . $l);

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
    
                self::prf($key, $R, $l, $R, $l, $i, $encrypt);
            }
            ubiq_debugv('R ' . implode(',', $R));
    
            // Step 6vi
            // calculate A +/- y mod radix**m
            // where y is the number formed by the first d bytes of R
            // create an integer from the first @d bytes in @R
            $c = self::stringToBigInteger($A, $alphabet);
            ubiq_debugv('c ' . $c->toString());
            ubiq_debugv('A ' . $A);
            ubiq_debugv('d ' . $d);

            $yA = array_slice($R, 0, $d);
            ubiq_debugv('yA ' . implode(',', $yA));
            $y = self::bytesToBigInteger($yA);
            ubiq_debugv('y ' . $y->toString());
            // $y = $y->modPow(self::$big_one, self::$big_one->bitwise_leftShift(8 * $d));
            $y = $y->modPow(self::$big_one, $big_radix_pow_m);
            ubiq_debugv('y ' . $y->toString());

            // Step 6vii
            if ($encrypt) {
                $c = $c->add($y);
            } else {
                $c = $c->subtract($y);
            }

            $c = $c->modPow(self::$big_one, $big_radix_pow_m);
            
            // the algorithm appears to need a number between 0 and the dominator,
            // this if statement prevents result to be negative.
            if ($c->compare(self::$big_zero) < 0) {
                $c = $c->add($big_radix_pow_m);
            }
            
            // Step 6viii
            $C = self::bigIntegerToString($c, $alphabet, $m);
            $A = $B;
            
            // Step 6ix
            $B = $C;

            ubiq_debugv('c ' . $c->toString());
            ubiq_debugv('A ' . $A);
            ubiq_debugv('B ' . $B);
            ubiq_debugv('C ' . $C);
        }
    
        // Step 7
        ubiq_debugv('final answer ' . ($encrypt ? ($A . $B) : ($B . $A)));
        return $encrypt ? ($A . $B) : ($B . $A);
    }

}    