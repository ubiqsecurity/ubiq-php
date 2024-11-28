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
 * Ubiq decryption object
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class Decryption
{
    private $_key_raw;
    private $_key_enc;
    private $_algorithm;

    private ?Dataset $_dataset = null;
    private ?Credentials $_creds = null;

    private $_iv;

    /**
     * Construct a new decryption object
     *
     * @param Credentials $creds   The credentials associated with the account
     *                             used to obtain the key
     * @param var         $dataset The dataset this operation is being performed on
     *                             Will default to null, which will be derived
     *                             based on access
     */
    public function __construct(
        Credentials $creds = null,
        $dataset = null
    ) {
        $this->_creds = $creds;

        if ($creds) {
            $this->_reset();
            $dataset = $creds::$datasetmanager->getDataset($creds, $dataset);
            $this->_dataset = $dataset;
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
     * Begin decryption of a new ciphertext
     *
     * No data has been provided, yet, so this function can't do anything.
     *
     * @return string A string containing the initial portion of the plaintext
     */
    public function begin() : string
    {
        // only unstructured has incremental
        if ($this->_dataset->type != DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
            throw new \Exception(
                'Invalid call to Decryption::begin() for dataset type of ' . $this->_dataset->type
            );
        }

        if (!is_null($this->_iv)) {
            throw new \Exception(
                'Decryption already in progress'
            );
        }

        $this->_creds::$eventprocessor->addOrIncrement(
            new Event([
                'api_key'                   => $this->_creds->getPapi(),
                'dataset_name'              => $this->_dataset->name,
                'dataset_group_name'        => $this->_dataset->group_name,
                'action'                    => EventProcessor::EVENT_TYPE_DECRYPT,
                'dataset_type'              => $this->_dataset->type,
                'key_number'                => 0,
            ])
        );

        $this->_iv = '';

        return '';
    }

    /**
     * Parse the ciphertext
     *
     * This function parses the header from the ciphertext. The original
     * ciphertext is unaltered. Any failure results in an exception.
     *
     * @param string $ciphertext The ciphertext (obviously containing
     *                           the header) to be parsed
     *
     * @return array An associative array containing the following elements:
     *         version, flags, algoid, iv, key_enc, and content
     */
    private function _ctparse(string &$ciphertext) : array
    {
        $header = unpack('Cversion', $ciphertext);
        if (!$header || $header['version'] != 0) {
            throw new \Exception(
                'failed to parse ciphertext header'
            );
        }

        $header = unpack(
            'Cversion/Cflags/Calgoid/Civlen/nkeylen', $ciphertext
        );
        if (!$header || (strlen($ciphertext) < 6 + $header['ivlen'] + $header['keylen'])) {
            throw new \Exception(
                'failed to parse ciphertext header'
            );
        }

        $header['iv'] = substr($ciphertext, 6, $header['ivlen']);
        $header['key_enc'] = substr(
            $ciphertext, 6 + $header['ivlen'], $header['keylen']
        );

        $header['content'] = substr(
            $ciphertext, 0, 6 + $header['ivlen'] + $header['keylen']
        );

        unset($header['keylen']);
        unset($header['ivlen']);

        return $header;
    }

    /**
     * Add the given ciphertext to the current decryption for unstructured
     *
     * @param string $ciphertext The ciphertext to be decrypted
     *
     * @return string A string containing a portion of the plaintext. This
     *         string should be appended to the string returned by the most
     *         recent call to either begin() or update()
     */
    public function update(string $ciphertext) : string
    {
        // only unstructured has incremental
        if ($this->_dataset->type != DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
            throw new \Exception(
                'Invalid call to Decryption::update() for dataset type of ' . $this->_dataset->type
            );
        }
        
        if (is_null($this->_iv)) {
            throw new \Exception(
                'update() called without begin()'
            );
        } else if (strlen($this->_iv) != 0) {
            throw new \Exception(
                'piecewise encryption not supported'
            );
        }

        $header = $this->_ctparse($ciphertext);
        $ciphertext = substr($ciphertext, strlen($header['content']));

        if (!is_null($this->_key_enc)) {
            if ($this->_key_enc != $header['key_enc']) {
                $this->_reset();
            }
        }

        $key = $this->_creds::$keymanager->getDecryptionKey(
            $this->_creds,
            $this->_dataset,
            $header
        );

        $this->_key_enc = $key['_key_enc'] ?? null;
        $this->_key_raw = $key['_key_raw'] ?? null;
        $this->_algorithm = $key['_algorithm'] ?? null;
        $this->_iv = $header['iv'];

        $aad = '';
        if ($header['flags'] & HEADER_V0_FLAG_AAD) {
            $aad = $header['content'];
        }
        $tag = '';
        if ($this->_algorithm->taglen) {
            $tag = substr($ciphertext, -$this->_algorithm->taglen);
            $ciphertext = substr($ciphertext, 0, -$this->_algorithm->taglen);
        }

        $pt = openssl_decrypt(
            $ciphertext,
            $this->_algorithm->name,
            $this->_key_raw,
            OPENSSL_RAW_DATA,
            $this->_iv, $tag, $aad
        );
        if (is_bool($pt)) {
            throw new \Exception(
                'authentication of decrypted data failed'
            );
        }

        return $pt;
    }

    /**
     * Decrypt the given ciphertext for structured
     *
     * @param string $ciphertext The ciphertext to be decrypted
     *
     * @return string A string containing the plaintext
     */
    public function decrypt_structured(string $ciphertext) : string
    {
        // only structured
        if ($this->_dataset->type != DatasetManager::DATASET_TYPE_STRUCTURED) {
            throw new \Exception(
                'Invalid call to Decryption::decrypt_structured() for dataset type of ' . $this->_dataset->type
            );
        }
        
        $parts = Structured::deconstructFromPartialRules($ciphertext, $this->_creds, $this->_dataset);
        $string = $parts['string'];

        $key_number = FF1::decodeKeyNumber($string, $this->_dataset);
        
        // if we are caching structured keys decrypted, we can cache the whole FF1 object
        $cache_ff1 = ($this->_creds::$config['key_caching']['structured'] && !$this->_creds::$config['key_caching']['encrypt']);
        if ($cache_ff1) {
            $cipher = $this->_creds::$cachemanager::get(CacheManager::CACHE_TYPE_GENERAL, 'ff1-' . $this->_dataset->name . '-' . $key_number);
        }

        if (empty($cipher)) {
            $key = $this->_creds::$keymanager->getDecryptionKey(
                $this->_creds,
                $this->_dataset,
                ['key_number' => $key_number]
            );

            $cipher = new FF1(
                $this->_creds,
                $key['_key_raw'],
                $this->_dataset->structured_config['tweak'],
                $this->_dataset->structured_config['input_character_set'],
                $this->_creds::$config['logging']['vvverbose'] ?? false
            );

            if ($cache_ff1) {
                $this->_creds::$cachemanager::set(
                    CacheManager::CACHE_TYPE_GENERAL,
                    'ff1-' . $this->_dataset->name . '-' . $key_number,
                    $cipher,
                    KeyManager::getCacheTTL($this->_creds)
                );
            }
        }

        $plaintext_str = $cipher->decryptToOutput($string, $this->_dataset);
        $plaintext_str = Structured::reconstructFromPartialRules($plaintext_str, $parts, $this->_creds, $this->_dataset);
        
        return $plaintext_str;
    }

    /**
     * End the current decryption process
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
                'Invalid call to Decryption::end() for dataset type of ' . $this->_dataset->type
            );
        }
        
        if (is_null($this->_iv)) {
            throw new \Exception(
                'end() called before begin()'
            );
        }

        $this->_iv = null;

        return '';
    }

    /**
     * Reset properties associated with the key
     *
     * If a key has been obtained/decrypted and used, then
     * let the server know how many times it was used. Then,
     * reset all properties associated with that key to their
     * initial values.
     *
     * @return None
     */
    private function _reset() : void
    {
        // report usage

        $this->_key_raw     = null;
        $this->_key_enc     = null;
        $this->_algorithm   = null;
    }

    /**
     * Destroy the decryption object
     */
    public function __destruct()
    {
        $this->_reset();
    }
}
