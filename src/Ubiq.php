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

foreach (array('Algorithm.php',
               'CacheManager.php',
               'Credentials.php',
               'Dataset.php',
               'Decryption.php',
               'Encryption.php',
               'EventProcessor.php',
               'KeyManager.php',
               'Request.php') as $file) {
    include implode(DIRECTORY_SEPARATOR, array(__DIR__, $file));
}

const VERSION = '0.0.2';
const HEADER_V0_FLAG_AAD = 1;
const DATASET_TYPE_STRUCTURED = 'structured';
const DATASET_TYPE_UNSTRUCTURED = 'unstructured';


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
    $enc = new Encryption($credentials, $dataset, $multiple_uses);

    $ct  = $enc->begin();
    $ct .= $enc->update($plaintext);
    $ct .= $enc->end();

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
function decrypt(Credentials $credentials, string $ciphertext, $dataset = null)
{
    $dec = new Decryption($credentials, $dataset);

    $pt  = $dec->begin();
    $pt .= $dec->update($ciphertext);
    $pt .= $dec->end();

    return $pt;
}

/**
 * Debug output
 *
 * @param object $credentials The credentials object
 * @param string $message     Debug
 *
 * @return None
 */
// @codingStandardsIgnoreLine
function ubiq_debug(Credentials $creds, string $msg)
{
    if (!empty($creds)
        && !empty($creds->config)
        && ($creds->config['debug'] ?? false)
    ) {
        echo (new \DateTime())->format('Y-m-d H:i:s.v ') . $msg . PHP_EOL;
    }
}
