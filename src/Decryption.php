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
    private $_session;
    private $_fingerprint;
    private $_algorithm;
    private $_fragment;

    private $key = null;
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
        $dataset = $creds::$datasetmanager->getDataset($creds, $dataset);

        $this->_creds = $creds;
        $this->_dataset = $dataset;

        if ($creds) {
            $this->_reset();
        }
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
     * Routes update method based on type of dataset (structured or unstructured)
     *
     * @param string $ciphertext The ciphertext to be decrypted
     *
     * @return string A string containing a portion of the plaintext. This
     *         string should be appended to the string returned by the most
     *         recent call to either begin() or update()
     */
    public function update(string $ciphertext) : string
    {
        // structured does not have incremental
        if ($this->_dataset->type == DatasetManager::DATASET_TYPE_STRUCTURED) {
            return $this->updateStructured($ciphertext);
        }
        elseif ($this->_dataset->type == DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
            return $this->updateUnstructured($ciphertext);
        }
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
    public function updateUnstructured(string $ciphertext) : string
    {
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

        $this->$key = $key;
        $this->_key_enc = $key['_key_enc'] ?? null;
        $this->_key_raw = $key['_key_raw'] ?? null;
        $this->_session = $key['_session'] ?? null;
        $this->_fingerprint = $key['_fingerprint'] ?? null;
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
    public function updateStructured(string $ciphertext) : string
    {
        $prefix_str = '';
        $suffix_str = '';
        $mask_str = '';
        $decrypt_str = $ciphertext;
        $passthrough_vals = str_split($this->_dataset->structured_config['passthrough']);
        $passthrough_chars = array_flip($passthrough_vals);

        foreach ($this->_dataset->structured_config['passthrough_rules'] as $action) {
            if ($action === Structured::ENCRYPTION_RULE_TYPE_PREFIX) {
                $prefix_str = substr($ciphertext, 0, $action['length']);
                $decrypt_str = substr($decrypt_str, $action['length']);

                ubiq_debug($this->_creds, 'Parsing for partial encryption prefix ' . $prefix_str . ' and remainder ' . $decrypt_str);
            }
            if ($action === Structured::ENCRYPTION_RULE_TYPE_SUFFIX) {
                $suffix_str = substr($ciphertext, -$action['length']);
                $decrypt_str = substr($decrypt_str, 0, $action['length']);

                ubiq_debug($this->_creds, 'Parsing for partial encryption suffix ' . $prefix_str . ' and remainder ' . $decrypt_str);
            }
        }

        if (!empty($passthrough_chars)) {
            $mask_str = $decrypt_str;
            $decrypt_str = str_replace($passthrough_vals, '', $decrypt_str);

            ubiq_debug($this->_creds, 'Parsing for partial encryption remove passthrough chars to result in ' . $decrypt_str);
        }

        $key = $this->_creds::$keymanager->getDecryptionKey(
            $this->_creds,
            $this->_dataset,
            ['key_number' => FF1::decodeKeyNumber($decrypt_str, $this->_dataset)]
        );

        $this->key = $key;
        $this->_key_enc = $key['_key_enc'] ?? null;
        $this->_key_raw = $key['_key_raw'] ?? null;
        $this->_session = $key['_session'] ?? null;
        $this->_fingerprint = $key['_fingerprint'] ?? null;
        $this->_algorithm = $key['_algorithm'] ?? null;

        $cipher = new FF1(
            $this->_creds,
            $this->_key_raw,
            $this->_dataset->structured_config['tweak'],
            $this->_dataset->structured_config['input_character_set'],
            $this->_creds::$config['logging']['vverbose'] ?? FALSE
        );

        $plaintext_str = $cipher->decryptToOutput($decrypt_str, $this->_dataset, $this->_key_enc);
        $formatted_str = '';

        $k = 0;
        for ($i = 0; $i < strlen($mask_str); $i++) {
            if (!array_key_exists($mask_str[$i], $passthrough_chars)) {
                $formatted_str .= $plaintext_str[$k];
                $k++;
            }
            else {
                $formatted_str .= $mask_str[$i];
            }
        }

        return $prefix_str . $formatted_str . $suffix_str;
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
        $this->_session     = null;
        $this->_fingerprint = null;
        $this->_algorithm   = null;
        $this->_fragment    = null;
    }

    /**
     * Destroy the decryption object
     */
    public function __destruct()
    {
        $this->_reset();
    }
}
