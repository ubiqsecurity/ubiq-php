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

    // AES-ECB object constructed once per FF1 instance so the key
    // schedule isn't recomputed on every prf() call (the Feistel loop
    // calls prf() 10+ times per cipher). CBC chaining is applied by
    // hand in prf() so the stateless ECB object is safe to reuse.
    private $_aes = null;

    // When the GMP extension is available its compiled arbitrary-precision
    // arithmetic replaces phpseclib's pure-PHP BigInteger for all Feistel
    // base-conversion and modular-arithmetic steps (~10-50x faster).
    private static bool $_use_gmp = false;



    
    private static function bytesToBigInteger($array)
    {
        if (self::$_use_gmp) {
            if (empty($array)) return gmp_init(0);
            $bin = '';
            foreach ($array as $b) {
                $bin .= chr($b & 0xFF);
            }
            return gmp_import($bin, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        }
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
    private static function modBigIntegers($a, $b)
    {
        if (self::$_use_gmp) {
            // gmp_mod returns non-negative result for positive divisor,
            // which is the correct floor-mod for Feistel arithmetic.
            return gmp_mod($a, $b);
        }
        list($div, $remainder) = $a->divide($b);
        return $a->subtract($b->multiply($div));
    }

    private static function bigIntegerToString($number, $alphabet, $desired_string_length = FALSE) {
        $result = '';
        $radix = mb_strlen($alphabet);
        $alphabet_chars = mb_str_split($alphabet);

        if (self::$_use_gmp) {
            $big_radix = gmp_init($radix);
            $cvt = $number;
            while (gmp_cmp($cvt, 0) > 0) {
                [$cvt, $remainder] = gmp_div_qr($cvt, $big_radix);
                $result = $alphabet_chars[gmp_intval($remainder)] . $result;
            }
        } else {
            $big_radix = new BigInteger($radix);
            $cvt = new BigInteger($number);
            while ($cvt->compare(self::$big_zero) > 0) {
                list($cvt, $remainder) = $cvt->divide($big_radix);
                $result = $alphabet_chars[(int)$remainder->toString()] . $result;
            }
        }

        if ($desired_string_length !== FALSE) {
            if (mb_strlen($result) > $desired_string_length) {
                throw new \Exception("Unable to convert big integer into {$desired_string_length} characters");
            }
            if (mb_strlen($result) < $desired_string_length) {
                $result = str_repeat($alphabet_chars[0], $desired_string_length - mb_strlen($result)) . $result;
            }
        }

        return $result;
    }

    private static function stringToBigInteger($number_string, $alphabet)
    {
        $radix = mb_strlen($alphabet);
        $alphabet_array = array_flip(mb_str_split($alphabet));
        $chars = mb_str_split($number_string);

        if (self::$_use_gmp) {
            $number = gmp_init(0);
            $big_radix = gmp_init($radix);
            foreach ($chars as $ch) {
                $idx = $alphabet_array[$ch] ?? false;
                if ($idx === false) {
                    throw new \Exception("Invalid character in number string: {$ch} in alphabet {$alphabet}");
                }
                $number = gmp_add(gmp_mul($number, $big_radix), $idx);
            }
            return $number;
        }

        $number = new BigInteger(0);
        $digit = new BigInteger(1);
        $big_radix = new BigInteger($radix);
        for ($i = count($chars) - 1; $i >= 0; $i--) {
            $idx = $alphabet_array[$chars[$i]] ?? false;
            if ($idx === false) {
                throw new \Exception("Invalid character in number string: {$chars[$i]} in alphabet {$alphabet}");
            }
            $number = $number->add($digit->multiply(new BigInteger($idx)));
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

    public function decryptToOutput($ciphertext, Dataset $dataset)
    {
        ubiq_debug(self::$_creds, 'Starting decryptToOutput for ' . $ciphertext, 2);

        $text = self::decodeKeyNumber($ciphertext, $dataset, TRUE);
        self::$verbose && ubiq_debug('text ' . $text);

        // convert to a big number in the output charset radix
        $text = self::stringToBigInteger($text, $dataset->structured_config['output_character_set']);
        ubiq_debug(self::$_creds, 'converted stringToBigInteger', 2);
        self::$verbose && ubiq_debug('text to input ' . $text->toString());

        // convert to a big number string in the input charset radix
        $text = self::bigIntegerToString($text, $dataset->structured_config['input_character_set'], mb_strlen($ciphertext));
        ubiq_debug(self::$_creds, 'converted bigIntegerToString', 2);
        self::$verbose && ubiq_debug('text to output ' . $text);

        $text = $this->decrypt($text);
        ubiq_debug(self::$_creds, 'Finished decryptToOutput for ' . $ciphertext . ' to ' . $text, 2);

        return $text;
    }
    
    public function encryptToOutput($text, Dataset $dataset, $key_number)
    {
        ubiq_debug(self::$_creds, 'Starting encryptToOutput for ' . $text, 2);

        // encrypt
        $ciphertext = $this->encrypt($text);
        self::$verbose && ubiq_debug('ciphertext ' . $ciphertext);

        // convert to a big number in the input charset radix
        $ciphertext = self::stringToBigInteger($ciphertext, $dataset->structured_config['input_character_set']);
        ubiq_debug(self::$_creds, 'converted stringToBigInteger', 2);
        self::$verbose && ubiq_debug('ciphertext to input ' . $ciphertext->toString());

        // convert that to a bignumber string in the output radix
        $ciphertext = self::bigIntegerToString($ciphertext, $dataset->structured_config['output_character_set'], mb_strlen($text));
        ubiq_debug(self::$_creds, 'converted bigIntegerToString', 2);
        self::$verbose && ubiq_debug('ciphertext to output ' . $ciphertext);

        $ciphertext = self::encodeKeyNumber($ciphertext, $dataset, $key_number);
        ubiq_debug(self::$_creds, 'encodeKeyNumber', 2);
        self::$verbose && ubiq_debug('ciphertext with key number ' . $ciphertext);

        ubiq_debug(self::$_creds, 'Finished encryptToOutput for ' . $text . ' to ' . $ciphertext, 2);

        return $ciphertext;
    }

    public static function decodeKeyNumber($text, Dataset $dataset, $return_text = FALSE)
    {
        self::$verbose && ubiq_debug('decodeKeyNumber from ' . $text . ' for dataset ' . $dataset->name);
        // Get the first character from the text
        $text_array = mb_str_split($text);
        $output_char_set_array = mb_str_split($dataset->structured_config['output_character_set']);
        
        $char_buf = $text_array[0];

        // Find the index of the character in the dataset's OutputCharacters
        $encoded_value = mb_strpos($dataset->structured_config['output_character_set'], $char_buf);
        self::$verbose && ubiq_debug('char_buf ' . $char_buf);
        
        // Calculate the ct_val
        $key_number = $encoded_value >> (int)$dataset->structured_config['msb_encoding_bits'];

        ubiq_debug(self::$_creds, 'Decoded key number ' . $key_number . ' in ' . $text . ' as ' . $text, 2);

        if ($return_text) {
            $encoded_value -= $key_number << (int)$dataset->structured_config['msb_encoding_bits'];
            $ch = $output_char_set_array[$encoded_value];

            $text_array[0] = $ch;
            $decoded_text = implode("", $text_array);

            ubiq_debug(self::$_creds, 'Replaced decoded key number ' . $key_number . ' from ' . $text . ' to ' . $decoded_text, 2);

            return $decoded_text;
        }

        return $key_number;
    }

    public static function encodeKeyNumber($text, Dataset $dataset, $key_number)
    {
        // Get the first character from the text
        $text_array = mb_str_split($text);
        $output_char_set_array = mb_str_split($dataset->structured_config['output_character_set']);
        $char_buf = $text_array[0];

        // Find the index of the character in the dataset's OutputCharacters
        $ct_val = mb_strpos($dataset->structured_config['output_character_set'], $char_buf);
        self::$verbose && ubiq_debug('char_buf ' . $char_buf);
        self::$verbose && ubiq_debug('ct_val ' . $ct_val);

        // Calculate the ct_val
        $ct_val += $key_number << (int)$dataset->structured_config['msb_encoding_bits'];
        self::$verbose && ubiq_debug('ct_val ' . $ct_val);

        // Get the character from OutputCharacters at the ct_val index
        $ch = $output_char_set_array[$ct_val];
        self::$verbose && ubiq_debug('ch ' . $ch);

        // Replace the character in the text
        $text_array[0] = $ch;
        $encoded_text = implode("", $text_array);

        ubiq_debug(self::$_creds, 'Encoded key number ' . $key_number . ' in ' . $text . ' as ' . $encoded_text, 2);

        return $encoded_text;
    }

    public function __construct(Credentials $creds, $key, $tweak, $alphabet, $verbose = false) {
        self::$_creds = $creds;
        self::$verbose = $verbose;
        
        ubiq_debug(self::$_creds, 'Starting FF1:_construct', 2);

        self::$big_zero = new BigInteger(0);

        if (!empty($alphabet)) {
            $radix = mb_strlen($alphabet);
        }

        $this->key = $key;
        $this->tweak = $tweak;
        $this->radix = $radix;
        $this->alphabet = $alphabet;

        // Key schedule computed once here; CBC applied by hand in prf().
        $this->_aes = new \phpseclib3\Crypt\AES('ecb');
        $this->_aes->setKey($this->key);
        $this->_aes->disablePadding();

        // Prefer GMP extension for BigInteger arithmetic; fall back to
        // phpseclib when GMP is absent.
        self::$_use_gmp = extension_loaded('gmp');
        ubiq_debug(self::$_creds, 'FF1 BigInteger backend: ' . (self::$_use_gmp ? 'gmp' : 'phpseclib'), 2);

        // FF1 and FF3-1 support a radix up to 65536, but the
        // implementation becomes increasingly difficult and
        // less useful in practice after the limits below.
        if ($radix < 2 || $radix > mb_strlen($alphabet))
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
        ubiq_debug(self::$_creds, 'Finished FF1:_construct', 2);
    }


    private function prf($src, $src_offset, &$dest, $dest_offset, $length = self::BLOCK_SIZE)
    {
        $src_length = sizeof($src) - $src_offset;

        // CBC-MAC over the input blocks with IV = 0, applied by hand
        // so the (stateless ECB) AES object can be reused across calls.
        // The IV / previous-ciphertext block starts as 16 zero bytes;
        // each block is XORed with the previous ciphertext before
        // encryption (standard CBC), and the final ciphertext block is
        // the PRF output. This is byte-for-byte equivalent to the prior
        // phpseclib CBC + enableContinuousBuffer implementation.
        $prev = array_fill(0, self::BLOCK_SIZE, 0);
        $encrypted = null;

        for ($i = 0; $i < $length && $i < $src_length; $i += self::BLOCK_SIZE) {
            $src_part = array_slice($src, $i + $src_offset, self::BLOCK_SIZE);
            $src_part = self::padToBlockSize($src_part, self::BLOCK_SIZE);

            // CBC: XOR previous ciphertext block into this plaintext block
            $xored = '';
            for ($k = 0; $k < self::BLOCK_SIZE; $k++) {
                $xored .= chr(($src_part[$k] ^ $prev[$k]) & 0xFF);
            }

            $encrypted = $this->_aes->encrypt($xored);
            $prev = array_values(unpack('C*', $encrypted));
        }

        $encrypted_arr = array_values(unpack('C*', $encrypted));

        // Adjust the destination buffer with the result
        array_splice($dest, $dest_offset, sizeof($encrypted_arr), $encrypted_arr);

        return $dest;
    }

    private static function bigInit(int $n) {
        return self::$_use_gmp ? gmp_init($n) : new BigInteger($n);
    }

    private static function bigPow($base, int $exp) {
        return self::$_use_gmp ? gmp_pow($base, $exp) : $base->pow(new BigInteger($exp));
    }

    private static function bigAdd($a, $b) {
        return self::$_use_gmp ? gmp_add($a, $b) : $a->add($b);
    }

    private static function bigSub($a, $b) {
        return self::$_use_gmp ? gmp_sub($a, $b) : $a->subtract($b);
    }

    private static function bigIsNeg($n): bool {
        return self::$_use_gmp ? (gmp_cmp($n, 0) < 0) : $n->isNegative();
    }

    private static function bigToByteArray($n): array {
        if (self::$_use_gmp) {
            if (gmp_cmp($n, 0) == 0) return [0];
            return array_values(unpack('C*', gmp_export($n, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN)));
        }
        return array_values(unpack('C*', $n->toBytes()));
    }

    private static function bigToString($n): string {
        return self::$_use_gmp ? gmp_strval($n) : $n->toString();
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
        $big_radix = self::bigInit($radix);

        $n = mb_strlen($x);
        $u = floor($n / 2);
        $v = $n - $u;

        // radix**m is needed every Feistel round, but m only ever
        // takes one of two values (u or v). Precompute both here
        // instead of recomputing the pow() inside the 10-round loop.
        $big_radix_pow_u = self::bigPow($big_radix, (int) $u);
        $big_radix_pow_v = self::bigPow($big_radix, (int) $v);
        
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
            $A = mb_substr($x, 0, $u);
            $B = mb_substr($x, $u);
        } else {
            $B = mb_substr($x, 0, $u);
            $A = mb_substr($x, $u);
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
    
            $big_radix_pow_m = ($m == $u) ? $big_radix_pow_u : $big_radix_pow_v;

            $c = 0;
            $y = 0;
            $numb = [];
            self::$verbose && ubiq_debug('b ' . $b);
            self::$verbose && ubiq_debug('sizeof($PQ) ' . sizeof($PQ));
    
            // Step 6i, the non-static parts
            $PQ[sizeof($PQ) - $b - 1] = ($encrypt ? $i : (9 - $i)) & 0xFF;
            self::$verbose && ubiq_debug('PQ ' . (sizeof($PQ) - $b - 1) . ' ' . $PQ[sizeof($PQ) - $b - 1]);
    
            // convert numeral string B to an integer
            // export that integer as a byte array in to q
            $c = self::stringToBigInteger($B, $alphabet);
            self::$verbose && ubiq_debug('c ' . self::bigToString($c));

            $numb = self::bigToByteArray($c);
            self::$verbose && ubiq_debug('numb ' . implode(',', $numb));

            if (array_key_exists(0, $numb) && $numb[0] == 0 && sizeof($numb) > 1) {
                // Remove the phpseclib sign byte when present (GMP never adds one)
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
            self::$verbose && ubiq_debug('c ' . self::bigToString($c));
            self::$verbose && ubiq_debug('A ' . $A);
            self::$verbose && ubiq_debug('d ' . $d);

            $yA = array_slice($R, 0, $d);
            self::$verbose && ubiq_debug('yA ' . implode(',', $yA));
            $y = self::bytesToBigInteger($yA);
            self::$verbose && ubiq_debug('y ' . self::bigToString($y));
            $y = self::modBigIntegers($y, $big_radix_pow_m);
            self::$verbose && ubiq_debug('y ' . self::bigToString($y));

            // Step 6vii
            if ($encrypt) {
                self::$verbose && ubiq_debug('c adding for encrypt ' . self::bigToString($y) . ' ' . self::bigToString($c));
                $c = self::bigAdd($c, $y);
            } else {
                $c = self::bigSub($c, $y);
                self::$verbose && ubiq_debug('c subtracting for decrypt ' . self::bigToString($y) . ' ' . self::bigToString($c));
            }

            $c = self::modBigIntegers($c, $big_radix_pow_m);

            // modBigIntegers (gmp_mod) is always non-negative for positive modulus,
            // so this guard only fires in the phpseclib path.
            self::$verbose && ubiq_debug('c is negative ' . (self::bigIsNeg($c) ? '1' : '0') . ' ' . self::bigToString($c));
            if (self::bigIsNeg($c)) {
                self::$verbose && ubiq_debug('c less than zero, adding ' . self::bigToString($c) . ' + ' . self::bigToString($big_radix_pow_m));
                $c = self::bigAdd($c, $big_radix_pow_m);
            }

            // Step 6viii
            $C = self::bigIntegerToString($c, $alphabet, $m);
            $A = $B;

            // Step 6ix
            $B = $C;

            self::$verbose && ubiq_debug('c ' . self::bigToString($c));
            self::$verbose && ubiq_debug('A ' . $A);
            self::$verbose && ubiq_debug('B ' . $B);
            self::$verbose && ubiq_debug('C ' . $C);
        }
    
        // Step 7
        self::$verbose && ubiq_debug('final answer ' . ($encrypt ? ($A . $B) : ($B . $A)));
        return $encrypt ? ($A . $B) : ($B . $A);
    }

}    