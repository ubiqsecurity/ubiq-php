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
    private $_key_raw, $_key_enc;
    private $_session, $_fingerprint;
    private $_algorithm, $_fragment;
    private $_creds, $_dataset;

    private $_iv;

    /**
     * Construct a new decryption object
     *
     * @param Credentials   $creds      The credentials associated with the account
     *                                  used to obtain the key
     * @param Dataset       $dataset    The dataset this operation is being performed on
     *                                  Will default to NULL, which will be derived based on access
     */
    public function __construct(
        Credentials $creds = NULL,
        $dataset = NULL
    )
    {
        $this->_dataset = new Dataset($dataset);
        $this->_creds = $creds;

        if ($creds) {
            $this->_reset();
        }
    }

    /**
     * Begin decryption of a new ciphertext
     *
     * No data has been provided, yet, so this function can't do anything.
     *
     * @return A string containing the initial portion of the plaintext
     */
    public function begin() : string
    {
        if (!is_null($this->_iv)) {
            throw new \Exception(
                'Decryption already in progress'
            );
        }

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
     * @return An associative array containing the following elements:
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
        if (!$header
            || (strlen($ciphertext) <
                // @codingStandardsIgnoreLine
                6 + $header['ivlen'] + $header['keylen'])
        ) {
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
     * Add the given ciphertext to the current decryption
     *
     * @param string $ciphertext The ciphertext to be decrypted
     *
     * @return A string containing a portion of the ciphertext. This
     *         string should be appended to the string returned by the most
     *         recent call to either begin() or update()
     */
    public function update(string $ciphertext) : string
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

        $key = $this->_creds->keycache->getDecryptionKey($this->_creds, $this->_dataset, $header);

        $this->_key_enc = $key['_key_enc'] ?? NULL;
        $this->_key_raw = $key['_key_raw'] ?? NULL;
        $this->_session = $key['_session'] ?? NULL;
        $this->_fingerprint = $key['_fingerprint'] ?? NULL;
        $this->_algorithm = $key['_algorithm'] ?? NULL;
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
     * End the current decryption process
     *
     * @return A string containing any remaining ciphertext or authentication
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
