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
                'Dataset.php',
                'DatasetManager.php',
                'Decryption.php',
                'Encryption.php',
                'EventProcessor.php',
                'FF1.php',
                'KeyManager.php',
                'Request.php',
                'Structured.php'
            ) as $file) {
    include implode(DIRECTORY_SEPARATOR, array(__DIR__, $file));
}


const VERSION = '2.0.1';
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
 * Caches keys for the named datasets
 *
 * @param object $credentials   The credentials object
 * @param array  $datasets      An array of strings for datasets to cache keys for
 *
 */
function primeKeyCache(
    Credentials $credentials,
    array $datasets
) {
    if (!$credentials->viable()) {
        throw new 
            \Exception('Credentials not loaded');
    }

    $keys = $credentials::$keymanager->getAllEncryptionKeys(
        $credentials,
        $datasets
    );
}

/**
 * Encrypt a given plaintext and retrieve all possible ciphertext variants
 * for keys (key rotations) that have been used
 *
 * @param object $credentials   The credentials object
 * @param string $plaintext     The plaintext data to be encrypted
 * @param string $dataset       The dataset being encrypted on
 *
 * @return array Returns an array of ciphertexts
 */
function encryptForSearch(
    Credentials $credentials,
    string $plaintext,
    $dataset = null
) {
    if (!$credentials->viable()) {
        throw new 
            \Exception('Credentials not loaded');
    }

    $keys = $credentials::$keymanager->getAllEncryptionKeys(
        $credentials,
        $dataset
    );

    $cts = [];

    foreach ($keys as $key_data) {
        $enc = new Encryption($credentials, $key_data['dataset'], false, $key_data['key']);

        $cts[] = $enc->encrypt_structured($plaintext);
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
