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
    private $_uses_cur;

    private $_iv;

    private $_baseurl;
    private $_http;
    private $_srsa;

    /**
     * Construct a new decryption object
     *
     * No request can be made of the server, yet, because the key
     * is attached to the data which has not yet been provided. This
     * function sets up the http request object and stores the key
     * from the credentials for later decryption of data from the
     * server.
     *
     * @param Credentials $creds The credentials associated with the account
     *                           used to obtain the key
     */
    public function __construct(Credentials $creds = null)
    {
        if ($creds) {
            $this->_baseurl = $creds->getHost() . '/api/v0/decryption/key';
            $this->_http = new Request(
                $creds->getPapi(), $creds->getSapi()
            );
            $this->_srsa = $creds->getSrsa();

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

        if (is_null($this->_key_enc)) {
            $resp = $this->_http->post(
                $this->_baseurl,
                json_encode(
                    array(
                        'encrypted_data_key' => base64_encode(
                            $header['key_enc']
                        )
                    )
                ),
                'application/json'
            );

            if (!$resp) {
                throw new \Exception(
                    'Request for decryption key failed'
                );
            } else if ($resp['status'] != 200) {
                throw new \Exception(
                    'Request for decryption key returned ' . $resp['status']
                );
            }

            $this->_algorithm   = new Algorithm($header['algoid']);

            $json = json_decode($resp['content'], true);

            $pkey = openssl_pkey_get_private(
                $json['encrypted_private_key'], $this->_srsa
            );
            openssl_private_decrypt(
                base64_decode($json['wrapped_data_key']),
                $this->_key_raw,
                $pkey,
                OPENSSL_PKCS1_OAEP_PADDING
            );
            $this->_key_enc     = $header['key_enc'];
            $this->_session     = $json['encryption_session'];
            $this->_fingerprint = $json['key_fingerprint'];
            $this->_uses_cur    = 0;
        }

        $this->_uses_cur++;
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
            $this->_algorithm->name, $this->_key_raw,
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
        if ($this->_session && $this->_uses_cur > 0) {
            $resp = $this->_http->patch(
                $this->_baseurl . '/' .
                $this->_fingerprint . '/' . $this->_session,
                json_encode(
                    array(
                        'uses' => $this->_uses_cur
                    )
                ),
                'application/json'
            );
        }

        $this->_key_raw     = null;
        $this->_key_enc     = null;
        $this->_session     = null;
        $this->_fingerprint = null;
        $this->_algorithm   = null;
        $this->_fragment    = null;
        $this->_uses_cur    = 0;
    }

    /**
     * Destroy the decryption object
     */
    public function __destruct()
    {
        $this->_reset();
    }
}
