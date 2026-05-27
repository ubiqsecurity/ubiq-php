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
 * Ubiq encryption object
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class Encryption
{

    private $_key_raw;
    private $_key_enc; // for structured, this is the encoded key number
    private $_algorithm;

    private ?Dataset $_dataset = null;
    private ?Credentials $_creds = null;

    private $_header;

    /**
     * Construct a new encryption object
     *
     * The constructor uses the supplied credentials and the requested
     * number of uses of the key to request a data encryption key from
     * the server. If the request is successful, the object prepares
     * the key for use by the begin(), update(), and end() series of
     * functions.
     *
     * Failures result in exceptions being thrown
     *
     * @param Credentials $creds         The credentials associated with the account
     *                                   used to obtain the key
     * @param var         $dataset       The dataset this operation is for
     *                                   Will default to null, which will be derived
     *                                   based on access
     * @param Bool        $multiple_uses If the encryption key should be re-used
     * @param string      $key           A key to be used to encrypt; if not provided,
     *                                   the current one will be fetched
     *                                   (optional)
     */
    public function __construct(
        Credentials $creds = null,
        $dataset = null,
        $multiple_uses = false,
        $key = NULL
    ) {

        if ($creds) {
            $dataset = $creds::$datasetmanager->getDataset($creds, $dataset);
        }

        if ($creds && empty($key)) {
            $key = $creds::$keymanager->getEncryptionKey(
                $creds,
                $dataset,
                (!$multiple_uses) && ($dataset->type == DatasetManager::DATASET_TYPE_UNSTRUCTURED)
            );
        }

        if (!empty($key)) {
            $this->_key_enc = $key['_key_enc'] ?? null;
            $this->_key_raw = $key['_key_raw'] ?? null;
            $this->_algorithm = $key['_algorithm'] ?? null;
            $this->_dataset = $dataset;
            $this->_creds = $creds;
        }
    }

    /**
     * Gets the type of the dataset being acted upon
     *
     * @return string A string containing the dataset type DatasetManager::DATASET_TYPE_STRUCTURED or DATASET_TYPE_UNSTRUCTURED
     */
    public function getDatasetType() : string
    {
        return $this->_dataset->type;
    }

    /**
     * @return Dataset|null The resolved dataset for this encryption.
     */
    public function getDataset(): ?Dataset
    {
        return $this->_dataset;
    }

    /**
     * Data types that require their own typed helper (encryptInteger,
     * encryptDate, encryptDateTime) and must not flow through the
     * plain string encrypt path. Anything not on this list — null,
     * "string", "token", future names — is treated as string and
     * runs through the standard encrypt_structured pipeline (which
     * is what ubiq-java and ubiq-dotnet do).
     */
    public const TYPED_DATA_TYPES = ['integer', 'date', 'datetime'];

    /**
     * Reject calls to the string-typed encrypt() entry point when the
     * dataset has a typed data_type that needs a dedicated helper.
     * "string", "token", null, and anything else fall through.
     */
    public static function guardStringDataType(Encryption $enc, string $action): void
    {
        $dataset = $enc->getDataset();
        if ($dataset === null) {
            return;
        }
        $dt = $dataset->getDataType();
        if (!in_array($dt, self::TYPED_DATA_TYPES, true)) {
            return;
        }
        throw new \Exception(
            "Dataset '" . $dataset->name . "' has data_type '" . $dt . "' — "
            . "use " . $action . ucfirst($dt) . "() instead of " . $action . "()"
        );
    }

    /**
     * Reject calls to encryptInteger() when the dataset isn't typed
     * as 'integer' or doesn't carry a data_type_config block.
     */
    public static function guardIntegerDataType(Dataset $dataset): void
    {
        if ($dataset->getDataType() !== 'integer') {
            throw new \Exception(
                "Dataset '" . $dataset->name . "' has data_type '"
                . ($dataset->getDataType() ?? 'null') . "' — expected 'integer'"
            );
        }
        if ($dataset->getDataTypeConfig() === null) {
            throw new \Exception(
                "Dataset '" . $dataset->name . "' is missing data_type_config"
            );
        }
    }

    /**
     * Range-check the value against the dataset's data_type_config and
     * render it as a base-10 string padded with leading '0's to
     * min_input_length. A leading '-' is preserved (and not counted
     * toward min_input_length) so the dataset's passthrough rule for
     * '-' handles the sign in the FF1 path.
     */
    /**
     * Reject encryptDate / decryptDate when the dataset isn't a 'date'.
     */
    public static function guardDateDataType(Dataset $dataset): void
    {
        if ($dataset->getDataType() !== 'date') {
            throw new \Exception(
                "Dataset '" . $dataset->name . "' has data_type '"
                . ($dataset->getDataType() ?? 'null') . "' — expected 'date'"
            );
        }
        if ($dataset->getDataTypeConfig() === null) {
            throw new \Exception(
                "Dataset '" . $dataset->name . "' is missing data_type_config"
            );
        }
    }

    /**
     * Reject encryptDateTime / decryptDateTime when the dataset isn't 'datetime'.
     */
    public static function guardDateTimeDataType(Dataset $dataset): void
    {
        if ($dataset->getDataType() !== 'datetime') {
            throw new \Exception(
                "Dataset '" . $dataset->name . "' has data_type '"
                . ($dataset->getDataType() ?? 'null') . "' — expected 'datetime'"
            );
        }
        if ($dataset->getDataTypeConfig() === null) {
            throw new \Exception(
                "Dataset '" . $dataset->name . "' is missing data_type_config"
            );
        }
    }

    /**
     * Number of whole days between $epoch and $date, taking the
     * date-only portion of each. Negative when $date precedes $epoch.
     * Both timestamps are interpreted in their respective timezones —
     * callers should normalize to UTC before invoking.
     */
    public static function daysBetween(\DateTimeImmutable $epoch, \DateTimeImmutable $date): int
    {
        $epochDate = $epoch->setTime(0, 0, 0);
        $dateOnly = $date->setTime(0, 0, 0);
        $epochSeconds = $epochDate->getTimestamp();
        $dateSeconds = $dateOnly->getTimestamp();
        return intdiv($dateSeconds - $epochSeconds, 86400);
    }

    /**
     * Number of seconds between $epoch and $date.
     */
    public static function secondsBetween(\DateTimeImmutable $epoch, \DateTimeImmutable $date): int
    {
        return $date->getTimestamp() - $epoch->getTimestamp();
    }

    /**
     * Render a non-negative base-10 integer as a base-N string in the
     * given alphabet, padded with the alphabet's "zero" character to
     * the requested length. Throws OutOfRangeException if the value
     * doesn't fit in `$length` characters. Used to bridge native ints
     * to a dataset's FF1 input or output alphabets — the alphabet
     * might be base-10 (integer / datetime), base-32 (date), etc.
     */
    public static function intToBaseN(int $value, string $alphabet, int $length): string
    {
        if ($value < 0) {
            throw new \InvalidArgumentException('intToBaseN: value must be non-negative; sign handled by caller');
        }
        $radix = mb_strlen($alphabet);
        if ($radix < 2) {
            throw new \InvalidArgumentException('intToBaseN: alphabet must have at least 2 chars');
        }
        $alphabetChars = mb_str_split($alphabet);
        $zero = $alphabetChars[0];

        if ($value === 0) {
            return str_repeat($zero, max($length, 1));
        }

        // $value is a native PHP int, so it always fits in 64-bit and
        // native modulo/division is exact — no BigInteger needed on the
        // encode side (Rust to_charset_radix pattern).
        $out = '';
        $n = $value;
        while ($n > 0) {
            $out = $alphabetChars[$n % $radix] . $out;
            $n = intdiv($n, $radix);
        }
        if (mb_strlen($out) < $length) {
            $out = str_repeat($zero, $length - mb_strlen($out)) . $out;
        }
        if ($length > 0 && mb_strlen($out) > $length) {
            throw new \OutOfRangeException(
                "intToBaseN: value $value does not fit in $length base-$radix characters"
            );
        }
        return $out;
    }

    /**
     * Inverse of {@see intToBaseN()}: parse a base-N string in the
     * given alphabet to a base-10 int. Throws if any character isn't
     * in the alphabet.
     *
     * Uses native int arithmetic when the value provably can't
     * overflow signed 64-bit (radix**length <= PHP_INT_MAX), falling
     * back to BigInteger only for the rare oversized case. Mirrors
     * ubiq-rust's from_charset_radix which stays in i64.
     */
    public static function intFromBaseN(string $value, string $alphabet): int
    {
        $radix = mb_strlen($alphabet);
        if ($radix < 2) {
            throw new \InvalidArgumentException('intFromBaseN: alphabet must have at least 2 chars');
        }
        $chars = mb_str_split($value);
        $alphabetMap = array_flip(mb_str_split($alphabet));

        // Native fast path: radix**len <= PHP_INT_MAX guarantees no
        // overflow. len * log(radix) < log(PHP_INT_MAX) is the same
        // test in log space, avoiding a pow() that could itself
        // overflow.
        if (count($chars) * log($radix) < log(PHP_INT_MAX)) {
            $result = 0;
            foreach ($chars as $ch) {
                if (!isset($alphabetMap[$ch])) {
                    throw new \RuntimeException("intFromBaseN: char '$ch' not in alphabet");
                }
                $result = $result * $radix + $alphabetMap[$ch];
            }
            return $result;
        }

        // BigInteger fallback for values that would overflow int64.
        $bigRadix = new \phpseclib3\Math\BigInteger($radix);
        $result = new \phpseclib3\Math\BigInteger(0);
        foreach ($chars as $ch) {
            if (!isset($alphabetMap[$ch])) {
                throw new \RuntimeException("intFromBaseN: char '$ch' not in alphabet");
            }
            $result = $result->multiply($bigRadix)->add(new \phpseclib3\Math\BigInteger($alphabetMap[$ch]));
        }
        return (int) $result->toString();
    }

    /**
     * True when the dataset has '-' in its passthrough character set,
     * meaning negative values can carry through FF1 via the
     * passthrough rule.
     */
    public static function passthroughIncludesMinus(Dataset $dataset): bool
    {
        $passthrough = (string) ($dataset->structured_config['passthrough'] ?? '');
        return mb_strpos($passthrough, '-') !== false;
    }

    /**
     * Range-check a value against the dataset's data_type_config and
     * encode it as a string in the dataset's input_character_set
     * alphabet, padded to min_input_length. Negative values are
     * prefixed with '-' when the dataset has a '-' passthrough rule;
     * datasets without one (e.g. date_2keys) reject negatives.
     *
     * Replaces the old base-10-only integerToPaddedDecimal which
     * silently produced wrong-alphabet strings for datasets like
     * date_2keys (input alphabet is base-32).
     */
    public static function integerToPaddedInputString(int $value, Dataset $dataset): string
    {
        $cfg = $dataset->getDataTypeConfig();
        if ($cfg !== null) {
            if ($cfg->minInputIntValue !== null && $value < $cfg->minInputIntValue) {
                throw new \OutOfRangeException("Value must be >= " . $cfg->minInputIntValue);
            }
            if ($cfg->maxInputIntValue !== null && $value > $cfg->maxInputIntValue) {
                throw new \OutOfRangeException("Value must be <= " . $cfg->maxInputIntValue);
            }
        }

        $alphabet = (string) ($dataset->structured_config['input_character_set'] ?? '');
        if ($alphabet === '') {
            throw new \RuntimeException("Dataset '" . $dataset->name . "' has no input_character_set");
        }
        $minLength = (int) ($dataset->structured_config['min_input_length'] ?? 0);
        $isNegative = $value < 0;
        if ($isNegative && !self::passthroughIncludesMinus($dataset)) {
            throw new \OutOfRangeException(
                "Dataset '" . $dataset->name . "' does not allow negative values"
            );
        }

        $encoded = self::intToBaseN(abs($value), $alphabet, $minLength);
        return $isNegative ? '-' . $encoded : $encoded;
    }

    /**
     * Render a base-10 int as a string in the dataset's
     * output_character_set alphabet, padded to min_input_length, so
     * it can be fed through decrypt_structured(). Used by the decrypt
     * side of typed methods to bridge ints back to FF1's expected
     * input shape.
     */
    public static function integerToPaddedOutputString(int $value, Dataset $dataset): string
    {
        $alphabet = (string) ($dataset->structured_config['output_character_set'] ?? '');
        if ($alphabet === '') {
            throw new \RuntimeException("Dataset '" . $dataset->name . "' has no output_character_set");
        }
        $minLength = (int) ($dataset->structured_config['min_input_length'] ?? 0);
        $isNegative = $value < 0;
        if ($isNegative && !self::passthroughIncludesMinus($dataset)) {
            throw new \OutOfRangeException(
                "Dataset '" . $dataset->name . "' does not allow negative values"
            );
        }
        $encoded = self::intToBaseN(abs($value), $alphabet, $minLength);
        return $isNegative ? '-' . $encoded : $encoded;
    }

    /**
     * Parse the cipher string returned by encrypt_structured() into a
     * base-10 int, interpreting the digit chars in the dataset's
     * output_character_set alphabet. A leading '-' is treated as
     * sign when the dataset has a '-' passthrough rule.
     */
    public static function parseCipherToInt(string $cipher, Dataset $dataset): int
    {
        $alphabet = (string) ($dataset->structured_config['output_character_set'] ?? '');
        if ($alphabet === '') {
            throw new \RuntimeException("Dataset '" . $dataset->name . "' has no output_character_set");
        }
        $isNegative = false;
        if (self::passthroughIncludesMinus($dataset) && strpos($cipher, '-') === 0) {
            $isNegative = true;
            $cipher = substr($cipher, 1);
        }
        $value = self::intFromBaseN($cipher, $alphabet);
        return $isNegative ? -$value : $value;
    }

    /**
     * Parse the plain string returned by decrypt_structured() (which
     * is in the dataset's input_character_set alphabet) back to a
     * base-10 int.
     */
    public static function parsePlainToInt(string $plain, Dataset $dataset): int
    {
        $alphabet = (string) ($dataset->structured_config['input_character_set'] ?? '');
        if ($alphabet === '') {
            throw new \RuntimeException("Dataset '" . $dataset->name . "' has no input_character_set");
        }
        $isNegative = false;
        if (self::passthroughIncludesMinus($dataset) && strpos($plain, '-') === 0) {
            $isNegative = true;
            $plain = substr($plain, 1);
        }
        $value = self::intFromBaseN($plain, $alphabet);
        return $isNegative ? -$value : $value;
    }

    /**
     * Deprecated — kept so the early-PR test file references still
     * load. Equivalent to {@see integerToPaddedInputString()} for
     * datasets whose input_character_set is base-10, which is the
     * only case the old name was correct for.
     *
     * @deprecated Use integerToPaddedInputString().
     */
    public static function integerToPaddedDecimal(int $value, Dataset $dataset): string
    {
        return self::integerToPaddedInputString($value, $dataset);
    }
    
    
    /**
     * Begin encryption of a new plaintext
     *
     * @return string A string containing the initial portion of the ciphertext
     */
    public function begin() : string
    {
        // only unstructured has incremental
        if ($this->_dataset->type != DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
            throw new \Exception(
                'Invalid call to Encryption::begin() for dataset type of ' . $this->_dataset->type
            );
        }

        if (!is_null($this->_header)) {
            throw new \Exception(
                'Encryption already in progress'
            );
        }

        $this->_creds::$eventprocessor->addOrIncrement(
            new Event([
                'api_key'                   => $this->_creds->getPapi(),
                'dataset_name'              => $this->_dataset->name,
                'dataset_group_name'        => $this->_dataset->group_name,
                'action'                    => EventProcessor::EVENT_TYPE_ENCRYPT,
                'dataset_type'              => $this->_dataset->type,
                'key_number'                => 0,
            ])
        );
        
        /*
         * there is an openssl_random_pseudo_bytes() function,
         * but whether it returns cryptographically strong random
         * data is system dependent. random_bytes() is always
         * cryptographically strong according to the manual.
         */
        $iv = random_bytes($this->_algorithm->ivlen);

        $flags = 0;
        if ($this->_algorithm->taglen > 0) {
            $flags |= HEADER_V0_FLAG_AAD;
        }

        $this->_header = pack(
            'CCCCn',
            0, /* version */
            $flags,
            $this->_algorithm->id,
            $this->_algorithm->ivlen,
            strlen($this->_key_enc)
        );

        $this->_header .= $iv;
        $this->_header .= $this->_key_enc;

        return $this->_header;
    }

    /**
     * Add the given plaintext to the current encryption
     *
     * @param string $plaintext The plaintext to be encrypted
     *
     * @return string A string containing a portion of the ciphertext. This
     *         string should be appended to the string returned by the most
     *         recent call to either begin() or update()
     */
    public function update(string $plaintext) : string
    {
        // only unstructured has incremental
        if ($this->_dataset->type != DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
            throw new \Exception(
                'Invalid call to Encryption::update() for dataset type of ' . $this->_dataset->type
            );
        }
        
        if (is_null($this->_header)) {
            throw new \Exception(
                'update() called without begin()'
            );
        }
        
        if (strlen($this->_header) == 0) {
            throw new \Exception(
                'piecewise encryption not supported'
            );
        }

        $iv = substr($this->_header, 6, $this->_algorithm->ivlen);

        $tag = '';
        $ct = openssl_encrypt(
            $plaintext,
            $this->_algorithm->name,
            $this->_key_raw,
            /*
             * we don't set the zero padding option, which means
             * that openssl will automatically add padding out to
             * the block size for algorithms that need it.
             */
            OPENSSL_RAW_DATA,
            $iv, $tag, $this->_header, $this->_algorithm->taglen
        );

        $this->_header = '';

        return $ct . $tag;
    }

    /**
     * Encrypt the given ciphertext for structured
     *
     * @param string $plaintext The plaintext to be decrypted
     *
     * @return string A string containing the ciphertext
     */
    public function encrypt_structured(
        $plaintext
    ) : string {
        // only structured
        if ($this->_dataset->type != DatasetManager::DATASET_TYPE_STRUCTURED) {
            throw new \Exception(
                'Invalid call to Encryption::encrypt_structured() for dataset type of ' . $this->_dataset->type
            );
        }

        $input_chars = array_flip(mb_str_split($this->_dataset->structured_config['input_character_set']));

        $parts = Structured::deconstructFromPartialRules($plaintext, $this->_creds, $this->_dataset);
        $string = $parts['string'];

        // Apply input_encoding (base64/base32) and input_pad_character padding
        // before validation, matching the Java/.NET pipeline order (encode → pad
        // → encrypt). When neither is configured, both are no-ops and behavior
        // is unchanged from prior releases.
        $string = \Ubiq\Pipeline\EncodeInputOperation::apply($string, $this->_dataset);
        $string = \Ubiq\Pipeline\PadInputOperation::apply($string, $this->_dataset);

        // Validate trimmed input
        foreach (mb_str_split($string) as $char) {
            if (!array_key_exists($char, $input_chars)) {
                throw new \Exception('Invalid character found in the input: ' . $char);
            }
        }
    
        if (mb_strlen($string) < $this->_dataset->structured_config['min_input_length']) {
            throw new \Exception('Invalid input length does not meet minimum of ' . $this->_dataset->structured_config['min_input_length']);
        }
    
        if (mb_strlen($string) > $this->_dataset->structured_config['max_input_length']) {
            throw new \Exception('Invalid input length exceeds maximum of ' . $this->_dataset->structured_config['max_input_length']);
        }

        // if we are caching structured keys decrypted, we can cache the whole FF1 object
        $cache_ff1 = ($this->_creds::$config['key_caching']['structured'] && !$this->_creds::$config['key_caching']['encrypt']);
        if ($cache_ff1) {
            $cipher = $this->_creds::$cachemanager::get(CacheManager::CACHE_TYPE_GENERAL, 'ff1-' . $this->_dataset->name . '-' . $this->_key_enc);
        }
        
        if (empty($cipher)) {
            $cipher = new FF1(
                $this->_creds,
                $this->_key_raw,
                $this->_dataset->structured_config['tweak'],
                $this->_dataset->structured_config['input_character_set'],
                $this->_creds::$config['logging']['vvverbose'] ?? false
            );

            if ($cache_ff1) {
                $this->_creds::$cachemanager::set(
                    CacheManager::CACHE_TYPE_GENERAL,
                    'ff1-' . $this->_dataset->name . '-' . $this->_key_enc,
                    $cipher,
                    KeyManager::getCacheTTL($this->_creds)
                );
            }
        }

        $cipher_str = $cipher->encryptToOutput($string, $this->_dataset, $this->_key_enc);
        $cipher_str = Structured::reconstructFromPartialRules($cipher_str, $parts, $this->_creds, $this->_dataset);

        return $cipher_str;
    }

    /**
     * End the current encryption process
     *
     * @return string A string containing any remaining ciphertext or authentication
     *         information. This string should be appended to the string
     *         returned by the most recent call to either begin() or update()
     */
    public function end() : string
    {
        // only unstructured has incremental
        if ($this->_dataset->type != DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
            throw new \Exception(
                'Invalid call to Encryption::end() for dataset type of ' . $this->_dataset->type
            );
        }
        
        if (is_null($this->_header)) {
            throw new \Exception(
                'end() called without begin()'
            );
        }

        $ret = '';

        if (strlen($this->_header) > 0) {
            $ret = $this->update('');
        }

        $this->_header = null;

        return $ret;
    }


    /**
     * Destroy the encryption object
     *
     * If the constructor successfully obtained a data key and that key
     * was used fewer times that was requested, this function will update
     * the server to reduce the count of encryptions performed.
     */
    public function __destruct()
    {
        // do event reporting
    }
}
