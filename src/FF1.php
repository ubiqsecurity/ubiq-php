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
    public static $verbose = false;

    private static ?BigInteger $big_zero = null;
    
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

    // https://stackoverflow.com/questions/1082917/mod-of-negative-number-is-melting-my-brain
    // return a - b * floor(a / b);
    // phpseclib\BigInteger::modPow doesn't seem to carry the negative
    private static function modBigIntegers(
        BigInteger $a,
        BigInteger $b
    ) : BigInteger {
        list($div, $remainder) = $a->divide($b);

        return $a->subtract($b->multiply($div));
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
        ubiq_debug(self::$_creds, 'Starting decryptToOutput for ' . $ciphertext);

        $text = self::decodeKeyNumber($ciphertext, $dataset, TRUE);
        self::$verbose && ubiq_debug('text ' . $text);

        // convert to a big number in the output charset radix
        $text = self::stringToBigInteger($text, $dataset->structured_config['output_character_set']);
        ubiq_debug(self::$_creds, 'converted stringToBigInteger');


        // convert to a big number string in the input charset radix
        $text = self::bigIntegerToString($text, $dataset->structured_config['input_character_set'], strlen($ciphertext));
        ubiq_debug(self::$_creds, 'converted bigIntegerToString');

        $text = $this->decrypt($text);
        ubiq_debug(self::$_creds, 'Finished decryptToOutput for ' . $ciphertext . ' to ' . $text);

        return $text;
    }
    
    public function encryptToOutput($text, Dataset $dataset, $key_number)
    {
        // encrypt
        $ciphertext = $this->encrypt($text);
        ubiq_debug(self::$_creds, 'Plaintext ' . $text . ' to ciphertext ' . $ciphertext);

        // convert to a big number in the input charset radix
        $ciphertext = self::stringToBigInteger($ciphertext, $dataset->structured_config['input_character_set']);
        self::$verbose && ubiq_debug('ciphertext ' . $ciphertext->toString());

        // convert that to a bignumber string in the output radix
        $ciphertext = self::bigIntegerToString($ciphertext, $dataset->structured_config['output_character_set'], strlen($text));
        self::$verbose && ubiq_debug('ciphertext ' . $ciphertext);

        $ciphertext = self::encodeKeyNumber($ciphertext, $dataset, $key_number);
        self::$verbose && ubiq_debug('ciphertext ' . $ciphertext);

        return $ciphertext;
    }

    public static function decodeKeyNumber($text, Dataset $dataset, $return_text = FALSE)
    {
        self::$verbose && ubiq_debug('decodeKeyNumber from ' . $text . ' for dataset ' . $dataset->name);
        // Get the first character from the text
        $char_buf = $text[0];

        // Find the index of the character in the dataset's OutputCharacters
        $encoded_value = strpos($dataset->structured_config['output_character_set'], $char_buf);
        self::$verbose && ubiq_debug('char_buf ' . $char_buf);
        
        // Calculate the ct_val
        $key_number = $encoded_value >> (int)$dataset->structured_config['msb_encoding_bits'];

        ubiq_debug(self::$_creds, 'Decoded key number ' . $key_number . ' in ' . $text . ' as ' . $text);

        if ($return_text) {
            $encoded_value -= $key_number << (int)$dataset->structured_config['msb_encoding_bits'];
            $ch = $dataset->structured_config['output_character_set'][$encoded_value];

            $decoded_text = $text;
            $decoded_text[0] = $ch;

            ubiq_debug(self::$_creds, 'Replaced decoded key number ' . $key_number . ' from ' . $text . ' to ' . $decoded_text);

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
        self::$verbose && ubiq_debug('output_character_set ' . $dataset->structured_config['output_character_set']);
        self::$verbose && ubiq_debug('char_buf ' . $char_buf);
        self::$verbose && ubiq_debug('ct_val ' . $ct_val);

        // Calculate the ct_val
        $ct_val += $key_number << (int)$dataset->structured_config['msb_encoding_bits'];
        self::$verbose && ubiq_debug('ct_val ' . $ct_val);

        // Get the character from OutputCharacters at the ct_val index
        $ch = $dataset->structured_config['output_character_set'][$ct_val];
        self::$verbose && ubiq_debug('ch ' . $ch);

        // Replace the character in the text
        $encoded_text = $text;
        $encoded_text[0] = $ch;

        ubiq_debug(self::$_creds, 'Encoded key number ' . $key_number . ' in ' . $text . ' as ' . $encoded_text);

        return $encoded_text;
    }

    public function __construct(Credentials $creds, $key, $tweak, $alphabet, $verbose = false) {
        self::$_creds = $creds;
        self::$verbose = $verbose;
        
        ubiq_debug(self::$_creds, 'Starting FF1:_construct');

        self::$big_zero = new BigInteger(0);

        if (!empty($alphabet)) {
            $radix = strlen($alphabet);
        }

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
        ubiq_debug(self::$_creds, 'Finished FF1:_construct');
    }


    private function prf($src, $src_offset, &$dest, $dest_offset, $length = self::BLOCK_SIZE)
    {
        // IV is 16 bytes of zero
        $iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
               
        self::$verbose && ubiq_debug('iv ' .  implode(',', $iv));
        // $iv = implode("", array_map("chr", $iv)); // make sure this is outside the loop
            
        $key = array_values(unpack('C*', $this->key));
        self::$verbose && ubiq_debug('key ' .  implode(',', $key));
        self::$verbose && ubiq_debug('src ' .  implode(',', $src));
        self::$verbose && ubiq_debug('dest ' .  implode(',', $dest));

        // OpenSSL encryption using AES-128-CBC with no padding
        $src_length = sizeof($src) - $src_offset;

        
        $aes = new \phpseclib3\Crypt\AES('cbc');
        $aes->setKey(implode("", array_map("chr", $key)));
        $aes->setIV(implode("", array_map("chr", $iv)));
        $aes->disablePadding();
        $aes->enableContinuousBuffer();

        self::$verbose && ubiq_debug('getEngine ' .  $aes->getEngine());

        for ($i = 0; $i < $length && $i < $src_length; $i += self::BLOCK_SIZE) {
            // Pad src_part to match the block size of self::BLOCK_SIZE bytes if necessary
            $src_part = array_slice($src, $i + $src_offset, self::BLOCK_SIZE);
            $src_part = self::padToBlockSize($src_part, self::BLOCK_SIZE);

            self::$verbose && ubiq_debug('src_part ' .  implode(',', $src_part));

            $encrypted = $aes->encrypt(implode("", array_map("chr", $src_part)));
            
            self::$verbose && ubiq_debug('encrypted phpseclib ' .  implode(',', array_values(unpack('C*', $encrypted))));

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
            // self::$verbose && ubiq_debug('encrypted openssl ' .  implode(',', array_values(unpack('C*', $encrypted))));

            if (!empty(openssl_error_string())) {
                ubiq_debug(self::$_creds, 'Structured encrypted OpenSSL error ' . openssl_error_string());
            }
        }
        self::$verbose && ubiq_debug('final encrypted ' .  implode(',', array_values(unpack('C*', $encrypted))));

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
        
        self::$verbose && ubiq_debug('x ' . $x);
        self::$verbose && ubiq_debug('n ' . $n);
        self::$verbose && ubiq_debug('u ' . $u);
    
        // Step 3, 4
        $a = intval(ceil((log($radix) / log(2)) * $v)) + 7;
        $b = intval($a / 8);
        $d = 4 * intval(($b + 3) / 4) + 4;
    
        $p = 16;
        $r = intval(($d + 15) / 16) * 16;
        self::$verbose && ubiq_debug('r ' . $r);
    
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
        self::$verbose && ubiq_debug('sizeof($tweak) ' . sizeof($tweak));
        self::$verbose && ubiq_debug('q ' . $q);
        
        // P and Q need to be adjacent in memory for encryption
        $PQ = array_fill(0, $p + $q, 0);
        $R = array_fill(0, $r, 0);
    
        self::$verbose && ubiq_debug('R ' . implode(',', $R));
        
        // Step 2
        if ($encrypt) {
            $A = substr($x, 0, $u);
            $B = substr($x, $u);
        } else {
            $B = substr($x, 0, $u);
            $A = substr($x, $u);
        }
        self::$verbose && ubiq_debug('A ' . $A);
        self::$verbose && ubiq_debug('B ' . $B);
        
    
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

        self::$verbose && ubiq_debug('PQ ' . implode(',', $PQ));

        // Step 6i, the static parts
        
        // if we allow tweaks, do this here
        
        for ($i = 0; $i < 10; $i++) {
            // Step 6v
            $m = (($i + ($encrypt ? 1 : 0)) % 2 == 1) ? $u : $v;
            self::$verbose && ubiq_debug('i ' . $i);
            self::$verbose && ubiq_debug('m ' . $m);
    
            $big_radix_pow_m = $big_radix->pow(new BigInteger($m));

            $c = 0;
            $y = 0;
            $numb = [];
            self::$verbose && ubiq_debug('b ' . $b);
            self::$verbose && ubiq_debug('sizeof($PQ) ' . sizeof($PQ));
    
            // Step 6i, the non-static parts
            $PQ[sizeof($PQ) - $b - 1] = ($encrypt ? $i : (9 - $i)) & 0xFF;
            self::$verbose && ubiq_debug('PQ ' . (sizeof($PQ) - $b - 1) . ' ' . (($encrypt ? $i : (9 - $i)) & 0xFF));
    
            // convert numeral string B to an integer
            // export that integer as a byte array in to q
            $c = self::stringToBigInteger($B, $alphabet);
            self::$verbose && ubiq_debug('c ' . $c->toString());

            // assume this is big-endian order because it came from the string
            $numb = array_values(unpack('C*', $c->toBytes()));
            self::$verbose && ubiq_debug('numb ' . implode(',', $numb));
    
            if ($numb[0] == 0 && sizeof($numb) > 1) {
                // Remove the extra byte if it exists
                array_shift($numb);
            }
            
            self::$verbose && ubiq_debug('sizeof($numb) ' . sizeof($numb));

            // Left pad with zeros
            if ($b > sizeof($numb)) {
                self::$verbose && ubiq_debug('adding zeros');
                $numb = self::padToBlockSize($numb, $b, 0);
            }
            array_splice($PQ, sizeof($PQ) - $b, $b, array_slice($numb, 0, $b));
            self::$verbose && ubiq_debug('PQ ' . implode(',', $PQ));

            // Step 6ii - perform encryption
            self::prf($PQ, 0, $R, 0, sizeof($PQ));
    
            // Step 6iii - fill subsequent blocks
            // with the result of ciph(R ^ 1), ciph(R ^ 2), ...
            self::$verbose && ubiq_debug('intval($r / 16) ' . intval($r / 16));
            
            for ($j = 1; $j < intval($r / 16); $j++) {
                $l = $j * 16;

                self::$verbose && ubiq_debug('l ' . $l);

                $R[$l + 0] = 0;
                $R[$l + 1] = 0;
                $R[$l + 2] = 0;
                $R[$l + 3] = 0;
                $R[$l + 4] = 0;
                $R[$l + 5] = 0;
                $R[$l + 6] = 0;
                $R[$l + 7] = 0;
                $R[$l + 8] = 0;
                $R[$l + 9] = 0;
                $R[$l + 10] = 0;
                $R[$l + 11] = 0;
                $R[$l + 12] = ($j >> 24) & 0xFF;
                $R[$l + 13] = ($j >> 16) & 0xFF;
                $R[$l + 14] = ($j >> 8) & 0xFF;
                $R[$l + 15] = ($j >> 0) & 0xFF;
                
                self::xorArray($R, $l, $R, 0, $R, $l, self::BLOCK_SIZE);
    
                self::prf($R, $l, $R, $l);
            }
            self::$verbose && ubiq_debug('R ' . implode(',', $R));
    
            // Step 6vi
            // calculate A +/- y mod radix**m
            // where y is the number formed by the first d bytes of R
            // create an integer from the first @d bytes in @R
            $c = self::stringToBigInteger($A, $alphabet);
            self::$verbose && ubiq_debug('c ' . $c->toString());
            self::$verbose && ubiq_debug('A ' . $A);
            self::$verbose && ubiq_debug('d ' . $d);

            $yA = array_slice($R, 0, $d);
            self::$verbose && ubiq_debug('yA ' . implode(',', $yA));
            $y = self::bytesToBigInteger($yA);
            self::$verbose && ubiq_debug('y ' . $y->toString());
            $y = self::modBigIntegers($y, $big_radix_pow_m);
            self::$verbose && ubiq_debug('y ' . $y->toString());

            // Step 6vii
            if ($encrypt) {
                self::$verbose && ubiq_debug('c adding for encrypt ' . $y->toString() . ' ' . $c->toString());
                $c = $c->add($y);
            } else {
                $c = $c->subtract($y);
                self::$verbose && ubiq_debug('c subtracting for decrypt ' . $y->toString() . ' ' . $c->toString());
            }

            $c = self::modBigIntegers($c, $big_radix_pow_m);

            // as noted in the nodeJS library
            // the algorithm appears to need a number between 0 and the dominator,
            // this if statement prevents result to be negative.
            self::$verbose && ubiq_debug('c is negative ' . $c->isNegative() . ' ' . $c->toString());
            if ($c->isNegative()) {
                self::$verbose && ubiq_debug('c less than zero, adding ' . $c->toString() . ' + ' . $big_radix_pow_m->toString());
                self::$verbose && ubiq_debug('$c->add($big_radix_pow_m) ' . $c->add($big_radix_pow_m)->toSTring());
                $c = $c->add($big_radix_pow_m);
            }
            
            // Step 6viii
            $C = self::bigIntegerToString($c, $alphabet, $m);
            $A = $B;
            
            // Step 6ix
            $B = $C;

            self::$verbose && ubiq_debug('c ' . $c->toString());
            self::$verbose && ubiq_debug('A ' . $A);
            self::$verbose && ubiq_debug('B ' . $B);
            self::$verbose && ubiq_debug('C ' . $C);
        }
    
        // Step 7
        self::$verbose && ubiq_debug('final answer ' . ($encrypt ? ($A . $B) : ($B . $A)));
        return $encrypt ? ($A . $B) : ($B . $A);
    }

}    