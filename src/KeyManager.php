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
 * Public object to manage key actions
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class KeyManager
{

    /**
     * Gets the default key for a dataset
     * Default key is found in {dataset name}-keys-default
     *
     * @param Credentials $creds   Credentials object to operate on
     * @param Dataset     $dataset Dataset to get a key for
     * 
     * @return Key data found in cache or false
     */
    public function getKeyDefault(Credentials $creds, Dataset $dataset)
    {
        $cache = $creds->cachemanager->get(
            CacheManager::CACHE_TYPE_KEYS, $dataset->name . '-keys-default'
        );
        
        if (!empty($cache)) {
            ubiq_debug($creds, 'Found default key of ' . $cache['key_idx'] . ' for ' . $dataset->name);

            return $this->getKey($creds, $dataset, $cache['_key_enc']);
        }

        return false;        
    }

    /**
     * Gets a key for a dataset
     * Expects unencoded encrypted_data_key
     *
     * @param Credentials $creds              Credentials object to operate on
     * @param Dataset     $dataset            Dataset to get a key for
     * @param string      $encrypted_data_key Data key to look for
     * 
     * @return Key data found in cache
     */
    public function getKey(
        Credentials $creds,
        Dataset $dataset,
        string $encrypted_data_key
    ) {
        $key_idx = md5(base64_encode($encrypted_data_key));

        ubiq_debug($creds, 'Looking for cached key for ' . $dataset->name . ' for key ' . $key_idx);

        $cache = $creds->cachemanager->get(
            CacheManager::CACHE_TYPE_KEYS,
            $dataset->name . '-keys-' . $key_idx
        );
        
        if (!empty($cache)) {
            ubiq_debug($creds, 'Found cached key for ' . $dataset->name . ' for key ' . $key_idx);
                
            $return = $cache;

            // if caching and encrypting, decrypt the key
            if ($creds->config['key_caching']['encrypt']) {
                ubiq_debug($creds, 'Cached keys are encrypted; decrypting prior to returning');
                
                $pkey = openssl_pkey_get_private(
                    $cache['_key_enc_prv'],
                    $creds->getSrsa()
                );

                $key_raw = null;

                openssl_private_decrypt(
                    $cache['_key_raw'],
                    $key_raw,
                    $pkey,
                    OPENSSL_PKCS1_OAEP_PADDING
                );

                $return['_key_raw'] = $key_raw;
            }

            return $return;
        }

        ubiq_debug($creds, 'Missed cached key for ' . $dataset->name . ' for key ' . $key_idx);

        return false;
    }

    /**
     * Adds key to cache
     *
     * @param Credentials $creds      Credentials object to operate on
     * @param Dataset     $dataset    Dataset to get a key for
     * @param array       $cache_data Data to cache for key
     * @param bool        $no_cache   Whether to skip caching and just return
     * 
     * @return Key data found in cache
     */    
    public function cacheKey(
        Credentials $creds,
        Dataset $dataset,
        array $cache_data,
        bool $no_cache = false
    ) {
        $key_idx = $cache_data['key_idx'];

        ubiq_debug($creds, 'Force disable cache ' . ($no_cache ? 'true' : 'false'));
        ubiq_debug($creds, 'Managing key for ' . $dataset->name . ' for key ' . $key_idx);

        // decrypt anyway for the return
        // but if caching and not encrypting, don't add it to the cache store
        $pkey = openssl_pkey_get_private(
            $cache_data['_key_enc_prv'],
            $creds->getSrsa()
        );

        $key_raw = null;
        openssl_private_decrypt(
            $cache_data['_key_raw'],
            $key_raw,
            $pkey,
            OPENSSL_PKCS1_OAEP_PADDING
        );

        if ($this->_shouldCache($creds, $dataset) && !$no_cache) {
            ubiq_debug($creds, 'Caching key for ' . $dataset->name . ' for key ' . $key_idx);

            if (!$creds->config['key_caching']['encrypt']) {
                ubiq_debug($creds, 'Cached keys are NOT encrypted; decrypting prior to cache');
            
                $cache_data['_key_raw'] = $key_raw;
            }

            $creds->cachemanager->set(
                CacheManager::CACHE_TYPE_KEYS,
                $dataset->name . '-keys-' . $key_idx, $cache_data
            );
        }

        $cache_data['_key_raw'] = $key_raw;
        // print_r($creds->cachemanager::$caches);
        return $cache_data;
    }

    /**
     * If the config says to cache
     *
     * @param Credentials $creds   Credentials object to operate on
     * @param Dataset     $dataset Dataset to get a key for
     * 
     * @return Bool
     */
    private function _shouldCache(Credentials $creds, Dataset $dataset)
    {
        $type = $dataset->type ?? DATASET_TYPE_UNSTRUCTURED;

        if ($type == DATASET_TYPE_UNSTRUCTURED) {
            ubiq_debug($creds, 'Key caching configuration for ' . DATASET_TYPE_UNSTRUCTURED . ' is ' . $creds->config['key_caching']['unstructured']);

            return ($creds->config['key_caching']['unstructured']);
        }

        return true;
    }

    /**
     * Get a key for encryption
     * Will get a default key if available
     * Will cache if appropriate
     *
     * @param Credentials $creds    Credentials object to operate on
     * @param Dataset     $dataset  Dataset to get a key for
     * @param bool        $no_cache Force no-cache
     * 
     * @return Array of key data
     */
    public function getEncryptionKey(
        Credentials $creds = null,
        Dataset $dataset = null,
        bool $no_cache = true
    ) {
        ubiq_debug($creds, 'Starting getEncryptionKey for ' . $dataset->name);

        if (!$creds) {
            throw new \Exception(
                'No valid credentials'
            );
            
            return;
        }

        $cache = $this->getKeyDefault($creds, $dataset);

        if (empty($cache)) {
            ubiq_debug($creds, 'Getting encryption key from backend for ' . $dataset->name);

            $http = new Request(
                $creds->getPapi(), $creds->getSapi()
            );

            $resp = $http->post(
                $creds->getHost() . '/api/v0/encryption/key',
                json_encode(['uses' => 1]),
                'application/json'
            );

            if (!$resp) {
                throw new \Exception(
                    'Request for encryption key failed'
                );

                return;
            } else if ($resp['status'] != 201) {
                throw new \Exception(
                    'Request for encryption key returned ' . $resp['status']
                );

                return;
            }
            
            $json = json_decode($resp['content'], true);

            $cache = [
                'key_idx'       => md5($json['encrypted_data_key']),
                '_key_enc'      => base64_decode($json['encrypted_data_key']),
                '_key_enc_prv'  => $json['encrypted_private_key'],
                '_key_raw'      => base64_decode($json['wrapped_data_key']),
                '_session'      => $json['encryption_session'],
                '_fingerprint'  => $json['key_fingerprint'],
                '_algorithm'    => new Algorithm(strtolower($json['security_model']['algorithm'])),
                '_fragment'     => $json['security_model']['enable_data_fragmentation']
            ];

            ubiq_debug($creds, 'Got encryption key from backend for ' . $dataset->name);
            
            // the return does decryption of key as needed
            $cache = $this->cacheKey($creds, $dataset, $cache, $no_cache);

            // if we're caching an encryption key, also cache it as the default
            if ($this->_shouldCache($creds, $dataset) && !$no_cache) {
                $creds->cachemanager->copy(CacheManager::CACHE_TYPE_KEYS, $dataset->name . '-keys-' . $cache['key_idx'], $dataset->name . '-keys-default');
            }
        }

        ubiq_debug($creds, 'Finished getEncryptionKey for ' . $dataset->name);

        return $cache;
    }

    /**
     * Get a key for decryption
     * Will cache if appropriate
     *
     * @param Credentials $creds       Credentials object to operate on
     * @param Dataset     $dataset     Dataset to get a key for
     * @param array       $key_headers Headers parsed from ciphertext
     * 
     * @return Array of key data
     */
    public function getDecryptionKey(
        Credentials $creds = null,
        Dataset $dataset = null,
        array $key_headers = []
    ) {
        ubiq_debug($creds, 'Starting getDecryptionKey for ' . $dataset->name);

        if (!$creds) {
            throw new \Exception(
                'No valid credentials'
            );
            
            return;
        }
        $cache = $this->getKey($creds, $dataset, $key_headers['key_enc']);

        if (empty($cache)) {
            ubiq_debug($creds, 'Getting decryption key from backend for ' . $dataset->name);

            $http = new Request(
                $creds->getPapi(), $creds->getSapi()
            );

            $resp = $http->post(
                $creds->getHost() . '/api/v0/decryption/key',
                json_encode(
                    ['encrypted_data_key' => base64_encode($key_headers['key_enc'])]
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

            $json = json_decode($resp['content'], true);

            $cache = [
                'key_idx'       => base64_encode(md5($key_headers['key_enc'])),
                '_key_enc'      => $key_headers['key_enc'],
                '_key_enc_prv'  => $json['encrypted_private_key'],
                '_key_raw'      => base64_decode($json['wrapped_data_key']),
                '_session'      => $json['encryption_session'],
                '_fingerprint'  => $json['key_fingerprint'],
                '_algorithm'    => new Algorithm($key_headers['algoid']),
            ];

            ubiq_debug($creds, 'Got decryption key from backend for ' . $dataset->name);

            // the return does decryption of key as needed
            $cache = $this->cacheKey($creds, $dataset, $cache);
        }

        ubiq_debug($creds, 'Finished getDecryptionKey for ' . $dataset->name);

        return $cache;
    }

    /**
     * Construct the keymanager object
     */
    public function __construct()
    {
    }

    /**
     * Destruct the keymanager object
     */
    public function __destruct()
    {
    }
}
