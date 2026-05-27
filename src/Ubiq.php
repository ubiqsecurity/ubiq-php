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
error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE | E_STRICT);

foreach (array(
                'Algorithm.php',
                'CacheManager.php',
                'Credentials.php',
                'DataTypeConfig.php',
                'Dataset.php',
                'DatasetManager.php',
                'Decryption.php',
                'Encryption.php',
                'EventProcessor.php',
                'FF1.php',
                'KeyManager.php',
                'Request.php',
                'Structured.php',
                'Pipeline/EncodeInputOperation.php',
                'Pipeline/DecodeInputOperation.php',
                'Pipeline/PadInputOperation.php'
            ) as $file) {
    include implode(DIRECTORY_SEPARATOR, array(__DIR__, $file));
}


const VERSION = '2.1.0';
const LIBRARY = 'ubiq-php';
const API_VERSION = 'V3';
const HEADER_V0_FLAG_AAD = 1;


/**
 * Encrypt a given plaintext
 *
 * @param object $credentials   The credentials object
 * @param string $plaintext     The plaintext data to be encrypted
 * @param string $dataset       The dataset being encrypted on
 * @param bool   $multiple_uses Whether or not this should cache
 *
 * @return string Returns an encryption of the plaintext
 */
function encrypt(
    Credentials $credentials,
    string $plaintext,
    $dataset = null,
    $multiple_uses = false
) {
    if (!$credentials->viable()) {
        throw new
            \Exception('Credentials not loaded');
    }

    ubiq_debug($credentials, 'Starting encrypt');

    $enc = new Encryption($credentials, $dataset, $multiple_uses);

    Encryption::guardStringDataType($enc, 'encrypt');

    if ($enc->getDatasetType() == DatasetManager::DATASET_TYPE_STRUCTURED) {
        $ct = $enc->encrypt_structured($plaintext);
    }
    elseif ($enc->getDatasetType() == DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
        $ct  = $enc->begin();
        $ct .= $enc->update($plaintext);
        $ct .= $enc->end();
    }

    ubiq_debug($credentials, 'Finished encrypt');

    return $ct;
}

/**
 * Encrypt a given integer plaintext on an integer-typed dataset.
 *
 * For datasets where data_type is "integer". The integer is rendered
 * as a leading-zero-padded decimal string, run through the existing
 * FF1 structured-encryption pipeline (negative sign handled via the
 * dataset's passthrough rules) and converted back to an int.
 *
 * Mirrors com.ubiqsecurity.UbiqStructuredEncryptDecrypt.encryptInt /
 * encryptLong (Java) and UbiqSecurity.UbiqStructuredEncryptDecrypt
 * .EncryptAsync(string, long) (.NET).
 *
 * @return int The encrypted integer
 */
function encryptInteger(
    Credentials $credentials,
    int $plaintext,
    $dataset = null
): int {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Encryption::guardIntegerDataType($dataset);

    // Render the int in the dataset's input_character_set alphabet
    // (base-10 for integer64/32). Sign carried by '-' passthrough.
    $plain_str = Encryption::integerToPaddedInputString($plaintext, $dataset);

    $enc = new Encryption($credentials, $dataset, false);
    $cipher_str = $enc->encrypt_structured($plain_str);

    // FF1 cipher digits live in the output_character_set alphabet
    // (base-14 for integer datasets). Parse back to base-10 int.
    return Encryption::parseCipherToInt($cipher_str, $dataset);
}

/**
 * Decrypt a given ciphertext
 *
 * @param object $credentials The credentials object
 * @param string $ciphertext  The cipher data to be decrypted
 * @param string $dataset     The dataset being decrypted
 *
 * @return string Returns an decryption of the ciphertext
 */
function decrypt(Credentials $credentials, string $ciphertext, string $dataset = null)
{
    if (!$credentials->viable()) {
        throw new
            \Exception('Credentials not loaded');
    }

    ubiq_debug($credentials, 'Starting decrypt');

    $dec = new Decryption($credentials, $dataset);
    Decryption::guardStringDataType($dec, 'decrypt');

    if ($dec->getDatasetType() == DatasetManager::DATASET_TYPE_STRUCTURED) {
        $pt = $dec->decrypt_structured($ciphertext);
    }
    elseif ($dec->getDatasetType() == DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
        $pt  = $dec->begin();
        $pt .= $dec->update($ciphertext);
        $pt .= $dec->end();
    }

    ubiq_debug($credentials, 'Finished decrypt');

    return $pt;
}

/**
 * Decrypt an integer ciphertext on an integer-typed dataset.
 *
 * Inverse of {@see encryptInteger()}. The integer ciphertext is
 * rendered as a leading-zero-padded decimal string (with a leading
 * '-' preserved for negatives), run through the existing FF1
 * structured-decryption pipeline, and converted back to an int.
 *
 * Mirrors com.ubiqsecurity.UbiqStructuredEncryptDecrypt.decryptInt /
 * decryptLong (Java) and UbiqSecurity.UbiqStructuredEncryptDecrypt
 * .DecryptAsync(string, long) (.NET).
 *
 * @return int The decrypted integer
 */
function decryptInteger(
    Credentials $credentials,
    int $ciphertext,
    $dataset = null
): int {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Decryption::guardIntegerDataType($dataset);

    // The cipher int is base-10. Render it in the dataset's
    // output_character_set alphabet (base-14) padded to
    // min_input_length so FF1 sees a length-correct input.
    $cipher_str = Encryption::integerToPaddedOutputString($ciphertext, $dataset);

    $dec = new Decryption($credentials, $dataset);
    $plain_str = $dec->decrypt_structured($cipher_str);

    // The decrypted plain is in input_character_set alphabet.
    return Encryption::parsePlainToInt($plain_str, $dataset);
}

/**
 * Encrypt a date plaintext on a date-typed dataset.
 *
 * The plain date is converted to days-from-epoch, run through the
 * FF1 structured pipeline (sign + zero-pad handled), and the
 * resulting encrypted day count is converted back to a date via
 * Epoch + days.
 *
 * The input must carry a UTC timezone — non-UTC inputs are rejected
 * to match the .NET behavior (UbiqStructuredEncryptDecrypt
 * .EncryptDateAsync) and avoid silent timezone drift.
 *
 * Mirrors com.ubiqsecurity.UbiqStructuredEncryptDecrypt.encryptDate
 * (Java) and EncryptDateAsync (.NET).
 *
 * @return \DateTimeImmutable The encrypted date (UTC)
 */
function encryptDate(
    Credentials $credentials,
    \DateTimeImmutable $plainDate,
    $dataset = null
): \DateTimeImmutable {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Encryption::guardDateDataType($dataset);

    _ubiq_require_utc($plainDate);

    $cfg = $dataset->getDataTypeConfig();
    $epoch = $cfg->epochAsDateTime() ?? new \DateTimeImmutable('0001-01-01T00:00:00Z');
    $minDate = $cfg->minInputDateAsDateTime();
    $maxDate = $cfg->maxInputDateAsDateTime();

    if ($minDate !== null && $plainDate->setTime(0, 0, 0) < $minDate->setTime(0, 0, 0)) {
        throw new \OutOfRangeException(
            'plainDate must be >= ' . $minDate->format('Y-m-d')
        );
    }
    if ($maxDate !== null && $plainDate->setTime(0, 0, 0) > $maxDate->setTime(0, 0, 0)) {
        throw new \OutOfRangeException(
            'plainDate must be <= ' . $maxDate->format('Y-m-d')
        );
    }

    $days = Encryption::daysBetween($epoch, $plainDate);
    // For date_2keys the input_character_set is base-32, so the days
    // count is encoded in base-32 padded to min_input_length (e.g. 4
    // chars). integerToPaddedInputString does the alphabet-aware
    // rendering.
    $plain_str = Encryption::integerToPaddedInputString($days, $dataset);

    $enc = new Encryption($credentials, $dataset, false);
    $cipher_str = $enc->encrypt_structured($plain_str);

    // Cipher digits are in output_character_set (base-41 for
    // date_2keys). Parse back to a base-10 int.
    $cipherDays = Encryption::parseCipherToInt($cipher_str, $dataset);
    return $epoch->setTime(0, 0, 0)->modify(sprintf('%+d days', $cipherDays));
}

/**
 * Decrypt a date ciphertext on a date-typed dataset.
 *
 * Inverse of {@see encryptDate()}.
 *
 * @return \DateTimeImmutable The original plaintext date (UTC)
 */
function decryptDate(
    Credentials $credentials,
    \DateTimeImmutable $cipherDate,
    $dataset = null
): \DateTimeImmutable {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Decryption::guardDateDataType($dataset);

    _ubiq_require_utc($cipherDate);

    $cfg = $dataset->getDataTypeConfig();
    $epoch = $cfg->epochAsDateTime() ?? new \DateTimeImmutable('0001-01-01T00:00:00Z');

    $cipherDays = Encryption::daysBetween($epoch, $cipherDate);
    // Render the cipher days in the dataset's output_character_set
    // alphabet so FF1 sees a length-correct input string.
    $cipher_str = Encryption::integerToPaddedOutputString($cipherDays, $dataset);

    $dec = new Decryption($credentials, $dataset);
    $plain_str = $dec->decrypt_structured($cipher_str);

    // Plain comes back in input_character_set alphabet.
    $plainDays = Encryption::parsePlainToInt($plain_str, $dataset);
    return $epoch->setTime(0, 0, 0)->modify(sprintf('%+d days', $plainDays));
}

/**
 * Encrypt a datetime plaintext on a datetime-typed dataset.
 *
 * Like {@see encryptDate()} but uses seconds-from-epoch so the
 * sub-day component is preserved.
 *
 * @return \DateTimeImmutable The encrypted datetime (UTC)
 */
function encryptDateTime(
    Credentials $credentials,
    \DateTimeImmutable $plainDate,
    $dataset = null
): \DateTimeImmutable {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Encryption::guardDateTimeDataType($dataset);

    _ubiq_require_utc($plainDate);

    $cfg = $dataset->getDataTypeConfig();
    $epoch = $cfg->epochAsDateTime() ?? new \DateTimeImmutable('0001-01-01T00:00:00Z');
    $minDate = $cfg->minInputDateAsDateTime();
    $maxDate = $cfg->maxInputDateAsDateTime();

    if ($minDate !== null && $plainDate < $minDate) {
        throw new \OutOfRangeException(
            'plainDate must be >= ' . $minDate->format(\DateTimeInterface::ATOM)
        );
    }
    if ($maxDate !== null && $plainDate > $maxDate) {
        throw new \OutOfRangeException(
            'plainDate must be <= ' . $maxDate->format(\DateTimeInterface::ATOM)
        );
    }

    $seconds = Encryption::secondsBetween($epoch, $plainDate);
    // datetime input_character_set is base-10 with '-' passthrough;
    // integerToPaddedInputString handles sign + padding.
    $plain_str = Encryption::integerToPaddedInputString($seconds, $dataset);

    $enc = new Encryption($credentials, $dataset, false);
    $cipher_str = $enc->encrypt_structured($plain_str);

    // Cipher digits are in output_character_set (base-12 for
    // datetime). Parse back to a signed int.
    $cipherSeconds = Encryption::parseCipherToInt($cipher_str, $dataset);
    return $epoch->modify(sprintf('%+d seconds', $cipherSeconds));
}

/**
 * Decrypt a datetime ciphertext on a datetime-typed dataset.
 *
 * @return \DateTimeImmutable The original plaintext datetime (UTC)
 */
function decryptDateTime(
    Credentials $credentials,
    \DateTimeImmutable $cipherDate,
    $dataset = null
): \DateTimeImmutable {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Decryption::guardDateTimeDataType($dataset);

    _ubiq_require_utc($cipherDate);

    $cfg = $dataset->getDataTypeConfig();
    $epoch = $cfg->epochAsDateTime() ?? new \DateTimeImmutable('0001-01-01T00:00:00Z');

    $cipherSeconds = Encryption::secondsBetween($epoch, $cipherDate);
    $cipher_str = Encryption::integerToPaddedOutputString($cipherSeconds, $dataset);

    $dec = new Decryption($credentials, $dataset);
    $plain_str = $dec->decrypt_structured($cipher_str);

    $plainSeconds = Encryption::parsePlainToInt($plain_str, $dataset);
    return $epoch->modify(sprintf('%+d seconds', $plainSeconds));
}

/**
 * @internal
 */
function _ubiq_require_utc(\DateTimeImmutable $date): void
{
    if ($date->getTimezone()->getName() !== 'UTC'
        && $date->getTimezone()->getName() !== '+00:00'
        && $date->getTimezone()->getName() !== 'Z'
    ) {
        throw new \InvalidArgumentException(
            'Date inputs to encrypt/decrypt Date/DateTime must be UTC; got '
            . $date->getTimezone()->getName()
        );
    }
}


/**
 * Cache dataset configs and encryption keys for one or more
 * structured datasets in a SINGLE network call. Subsequent calls
 * into encrypt / encryptInteger / encryptDate / encryptForSearch on
 * those datasets hit the cache and avoid per-dataset HTTP round
 * trips.
 *
 * Named to match ubiq-go's `structuredContext.loadCache` flow.
 * ubiq-java has an equivalent internal helper (`getFpeDefKeys`) but
 * no public wrapper.
 *
 *   - omit \$datasets (or pass [] / null) to fetch every dataset the
 *     API key has access to
 *   - pass an array of names to scope the prefetch
 *   - pass a single string name to prefetch one dataset
 *
 * @param Credentials       $credentials The credentials object
 * @param array|string|null $datasets    Optional list of dataset
 *                                       names. Empty / null fetches
 *                                       every dataset accessible to
 *                                       the API key.
 *
 * @return void Cache side-effects only.
 */
function loadCache(
    Credentials $credentials,
    $datasets = null
): void {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $credentials::$keymanager->getAllEncryptionKeys($credentials, $datasets);
}

/**
 * Encrypt a given plaintext and retrieve all possible ciphertext variants
 * for keys (key rotations) that have been used.
 *
 * @param Credentials $credentials The credentials object
 * @param string      $plaintext   The plaintext data to be encrypted
 * @param mixed       $dataset     The dataset being encrypted on
 *
 * @return string[] Returns an array of ciphertexts, one per key rotation
 */
function encryptForSearch(
    Credentials $credentials,
    string $plaintext,
    $dataset = null
): array {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    // Resolve and guard up front so a typed dataset bails out before
    // we fetch every key revision from the server. Only the
    // explicitly typed data_types (Encryption::TYPED_DATA_TYPES) are
    // rejected — "string" / "token" / null fall through.
    $resolved = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    $dt = $resolved->getDataType();
    if (in_array($dt, Encryption::TYPED_DATA_TYPES, true)) {
        throw new \Exception(
            "Dataset '" . $resolved->name . "' has data_type '" . $dt
            . "' — use encrypt" . ucfirst($dt) . "ForSearch() instead of encryptForSearch()"
        );
    }

    $keys = $credentials::$keymanager->getAllEncryptionKeys($credentials, $resolved);

    $cts = [];
    foreach ($keys as $key_data) {
        $enc = new Encryption($credentials, $key_data['dataset'], false, $key_data['key']);
        $cts[] = $enc->encrypt_structured($plaintext);
    }

    return $cts;
}

/**
 * Encrypt an integer across every active key on an integer-typed
 * dataset. Returns the ciphertext set you'd need to search an
 * encrypted column where the row could have been written under any
 * historical key rotation.
 *
 * Mirrors com.ubiqsecurity.UbiqStructuredEncryptDecrypt
 * .encryptIntForSearch / encryptLongForSearch (Java) and
 * UbiqSecurity.UbiqStructuredEncryptDecrypt.EncryptForSearchAsync
 * (.NET).
 *
 * @return int[] One ciphertext per key rotation.
 */
function encryptIntegerForSearch(
    Credentials $credentials,
    int $plaintext,
    $dataset = null
): array {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Encryption::guardIntegerDataType($dataset);

    $plain_str = Encryption::integerToPaddedInputString($plaintext, $dataset);

    $keys = $credentials::$keymanager->getAllEncryptionKeys($credentials, $dataset);

    $cts = [];
    foreach ($keys as $key_data) {
        $enc = new Encryption($credentials, $key_data['dataset'], false, $key_data['key']);
        $cipher_str = $enc->encrypt_structured($plain_str);
        $cts[] = Encryption::parseCipherToInt($cipher_str, $key_data['dataset']);
    }

    return $cts;
}

/**
 * Encrypt a date across every active key on a date-typed dataset.
 *
 * Mirrors com.ubiqsecurity.UbiqStructuredEncryptDecrypt
 * .encryptDateForSearch (Java) and EncryptDateForSearchAsync (.NET).
 *
 * @return \DateTimeImmutable[] One UTC date per key rotation.
 */
function encryptDateForSearch(
    Credentials $credentials,
    \DateTimeImmutable $plainDate,
    $dataset = null
): array {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Encryption::guardDateDataType($dataset);

    _ubiq_require_utc($plainDate);

    $cfg = $dataset->getDataTypeConfig();
    $epoch = $cfg->epochAsDateTime() ?? new \DateTimeImmutable('0001-01-01T00:00:00Z');
    $minDate = $cfg->minInputDateAsDateTime();
    $maxDate = $cfg->maxInputDateAsDateTime();

    if ($minDate !== null && $plainDate->setTime(0, 0, 0) < $minDate->setTime(0, 0, 0)) {
        throw new \OutOfRangeException(
            'plainDate must be >= ' . $minDate->format('Y-m-d')
        );
    }
    if ($maxDate !== null && $plainDate->setTime(0, 0, 0) > $maxDate->setTime(0, 0, 0)) {
        throw new \OutOfRangeException(
            'plainDate must be <= ' . $maxDate->format('Y-m-d')
        );
    }

    $days = Encryption::daysBetween($epoch, $plainDate);
    $plain_str = Encryption::integerToPaddedInputString($days, $dataset);

    $keys = $credentials::$keymanager->getAllEncryptionKeys($credentials, $dataset);

    $cts = [];
    foreach ($keys as $key_data) {
        $enc = new Encryption($credentials, $key_data['dataset'], false, $key_data['key']);
        $cipher_str = $enc->encrypt_structured($plain_str);
        $cipherDays = Encryption::parseCipherToInt($cipher_str, $key_data['dataset']);
        $cts[] = $epoch->setTime(0, 0, 0)->modify(sprintf('%+d days', $cipherDays));
    }

    return $cts;
}

/**
 * Encrypt a datetime across every active key on a datetime-typed
 * dataset.
 *
 * Mirrors com.ubiqsecurity.UbiqStructuredEncryptDecrypt
 * .encryptDateTimeForSearch (Java) and EncryptDateTimeForSearchAsync
 * (.NET).
 *
 * @return \DateTimeImmutable[] One UTC datetime per key rotation.
 */
function encryptDateTimeForSearch(
    Credentials $credentials,
    \DateTimeImmutable $plainDate,
    $dataset = null
): array {
    if (!$credentials->viable()) {
        throw new \Exception('Credentials not loaded');
    }

    $dataset = $credentials::$datasetmanager->getDataset($credentials, $dataset);
    Encryption::guardDateTimeDataType($dataset);

    _ubiq_require_utc($plainDate);

    $cfg = $dataset->getDataTypeConfig();
    $epoch = $cfg->epochAsDateTime() ?? new \DateTimeImmutable('0001-01-01T00:00:00Z');
    $minDate = $cfg->minInputDateAsDateTime();
    $maxDate = $cfg->maxInputDateAsDateTime();

    if ($minDate !== null && $plainDate < $minDate) {
        throw new \OutOfRangeException(
            'plainDate must be >= ' . $minDate->format(\DateTimeInterface::ATOM)
        );
    }
    if ($maxDate !== null && $plainDate > $maxDate) {
        throw new \OutOfRangeException(
            'plainDate must be <= ' . $maxDate->format(\DateTimeInterface::ATOM)
        );
    }

    $seconds = Encryption::secondsBetween($epoch, $plainDate);
    $plain_str = Encryption::integerToPaddedInputString($seconds, $dataset);

    $keys = $credentials::$keymanager->getAllEncryptionKeys($credentials, $dataset);

    $cts = [];
    foreach ($keys as $key_data) {
        $enc = new Encryption($credentials, $key_data['dataset'], false, $key_data['key']);
        $cipher_str = $enc->encrypt_structured($plain_str);
        $cipherSeconds = Encryption::parseCipherToInt($cipher_str, $key_data['dataset']);
        $cts[] = $epoch->modify(sprintf('%+d seconds', $cipherSeconds));
    }

    return $cts;
}

/**
 * Debug output
 * config[logging][verbose] will enable this output
 * config[logging][vverbose] will enable additional output logged with a #2 verbosity
 * config[logging][vvverbose] will enable additional output from FF1
 *
 * @param var    $credentials The credentials object or a $message
 * @param string $message     Debug
 *
 * @return None
 */
// @codingStandardsIgnoreLine
function ubiq_debug($creds, string $msg = NULL, $verbosity_level = 1)
{
    if (is_string($creds)) {
        echo (new \DateTime())->format('Y-m-d H:i:s.v ') . $creds . PHP_EOL;
    }
    elseif (
        !empty($creds)
        && !empty($creds::$config)
        && ($creds::$config['logging']['verbose'] ?? false)
        && ($verbosity_level == 1 || ($creds::$config['logging']['vverbose'] ?? false) == true)
    ) {
        echo (new \DateTime())->format('Y-m-d H:i:s.v ') . $msg . PHP_EOL;
    }
}
