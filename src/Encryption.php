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
    private $_key_enc;
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
     * Begin encryption of a new plaintext
     *
     * @return string A string containing the initial portion of the ciphertext
     */
    public function begin() : string
    {

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
        
        // structured does not have incremental
        if ($this->_dataset->type == DatasetManager::DATASET_TYPE_STRUCTURED) {
            return '';
        }

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
     * Routes update method based on type of dataset (structured or unstructured)
     *
     * @param string $plaintext The ciphertext to be decrypted
     *
     * @return string A string containing a portion of the ciphertext. This
     *         string should be appended to the string returned by the most
     *         recent call to either begin() or update()
     */
    public function update(string $plaintext) : string
    {
        // structured does not have incremental
        if ($this->_dataset->type == DatasetManager::DATASET_TYPE_STRUCTURED) {
            return $this->updateStructured($plaintext);
        }
        elseif ($this->_dataset->type == DatasetManager::DATASET_TYPE_UNSTRUCTURED) {
            return $this->updateUnstructured($plaintext);
        }
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
    public function updateUnstructured(string $plaintext) : string
    {
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
    public function updateStructured(
        $plaintext
    ) : string {
        $input_chars = array_flip(mb_str_split($this->_dataset->structured_config['input_character_set']));

        $parts = Structured::deconstructFromPartialRules($plaintext, $this->_creds, $this->_dataset);
        $string = $parts['string'];

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
    
        $cipher = new FF1(
            $this->_creds,
            $this->_key_raw,
            $this->_dataset->structured_config['tweak'],
            $this->_dataset->structured_config['input_character_set'],
            $this->_creds::$config['logging']['vverbose'] ?? FALSE
        );

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

        // structured does not have incremental
        if ($this->_dataset->type == DatasetManager::DATASET_TYPE_STRUCTURED) {
            return '';
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
