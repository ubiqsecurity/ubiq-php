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
 * Public object in which to store Ubiq credentials
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class KeyCache
{
    // [
    //     '_key_enc'      => DECODED encrypted data key
    //     '_key_enc_prv'  => encrypted private key (for the wrapper)
    //     '_key_raw'      => DECODED data key, either encrypted (wrapped) or decrypted based on config
    //     '_session'      => encryption session
    //     '_fingerprint'  => key fingerprint
    //     '_algorithm'    => new Algorithm()
    //     '_fragment'     => ['security_model']['enable_data_fragmentation']
    // ]
    public $cache = [];

    // for use from encryption when it is not
    // an explicit key material to lookup
    public function getKeyFromIndex($creds, $dataset, $idx)
    {
        return $this->getKey($creds, $dataset, $idx, TRUE);
    }

    // expects UNENCODED encrypted_data_key
    public function getKey($creds, $dataset, $encrypted_data_key, $key_lookup_is_idx = FALSE)
    {
        $key_idx = md5(base64_encode($encrypted_data_key));

        if ($key_lookup_is_idx) {
            if (array_key_exists($dataset->name, $this->cache)) {
                if (array_key_exists('keys', $this->cache[$dataset->name])) {
                    $key_idx = array_values($this->cache[$dataset->name]['keys'])[$encrypted_data_key]['key_idx'];

                    ubiq_debug($creds, 'Using cached key for ' . $dataset->name . ' for index ' . $encrypted_data_key);
                }
            }
        }

        ubiq_debug($creds, 'Looking for cached key for ' . $dataset->name . ' for key ' . $key_idx);

        if (array_key_exists($dataset->name, $this->cache)) {
            if (array_key_exists($key_idx, $this->cache[$dataset->name]['keys'])) {
                ubiq_debug($creds, 'Found cached key for ' . $dataset->name . ' for key ' . $key_idx);
                
                $return = $this->cache[$dataset->name]['keys'][$key_idx];

                // if caching and encrypting, decrypt the key
                if ($creds->config['key_caching']['encrypt']) {
                    ubiq_debug($creds, 'Cached keys are encrypted; decrypting prior to returning');
                    
                    $pkey = openssl_pkey_get_private(
                        $this->cache[$dataset->name]['keys'][$key_idx]['_key_enc_prv'],
                        $creds->getSrsa()
                    );

                    $key_raw = NULL;

                    openssl_private_decrypt(
                        $this->cache[$dataset->name]['keys'][$key_idx]['_key_raw'],
                        $key_raw,
                        $pkey,
                        OPENSSL_PKCS1_OAEP_PADDING
                    );

                    $return['_key_raw'] = $key_raw;
                }

                return $return;
            }
        }

        ubiq_debug($creds, 'Missed cached key for ' . $dataset->name . ' for key ' . $key_idx);

        return FALSE;
    }

    public function cacheKey($creds, $dataset, $cache_data, $no_cache = FALSE)
    {
        $key_idx = $cache_data['key_idx'];

        ubiq_debug($creds, 'Force disable cache ' . ($no_cache ? 'true' : 'false'));
        ubiq_debug($creds, 'Managing key for ' . $dataset->name . ' for key ' . $key_idx);

        // decrypt anyway for the return
        // but if caching and not encrypting, don't add it to the cache store
        $pkey = openssl_pkey_get_private(
            $cache_data['_key_enc_prv'],
            $creds->getSrsa()
        );

        $key_raw = NULL;
        openssl_private_decrypt(
            $cache_data['_key_raw'],
            $key_raw,
            $pkey,
            OPENSSL_PKCS1_OAEP_PADDING
        );

        if ($this->shouldCache($creds, $dataset) && !$no_cache) {
            ubiq_debug($creds, 'Caching key for ' . $dataset->name . ' for key ' . $key_idx);

            if (!$creds->config['key_caching']['encrypt']) {
                ubiq_debug($creds, 'Cached keys are NOT encrypted; decrypting prior to cache');
            
                $cache_data['_key_raw'] = $key_raw;
            }

            if (!array_key_exists($dataset->name, $this->cache)) {
                $this->cache[$dataset->name] = ['keys' => []];
            }
            $this->cache[$dataset->name]['keys'][$key_idx] = $cache_data;
        }

        $cache_data['_key_raw'] = $key_raw;
        return $cache_data;
    }

    private function shouldCache($creds, $dataset)
    {
        $type = $dataset->type ?? DATASET_TYPE_UNSTRUCTURED;

        if ($type == DATASET_TYPE_UNSTRUCTURED) {
            ubiq_debug($creds, 'Key caching configuration for ' . DATASET_TYPE_UNSTRUCTURED . ' is ' . $creds->config['key_caching']['unstructured']);

            return ($creds->config['key_caching']['unstructured']);
        }

        return TRUE;
    }

    public function getEncryptionKey(
        Credentials $creds = NULL,
        $dataset = NULL,
        $nocache = TRUE,
        $encryption_key_rotation_idx = 0 // the default encryption key from cache to use
    )
    {
        ubiq_debug($creds, 'Starting getEncryptionKey for ' . $dataset->name);

        if (!$creds) {
            throw new \Exception(
                'No valid credentials'
            );
            
            return;
        }

        $cache = $this->getKeyFromIndex($creds, $dataset, $encryption_key_rotation_idx);

        if (empty($cache)) {
            ubiq_debug($creds, 'Getting encryption key from backend for ' . $dataset->name);

            $http = new Request(
                $creds->getPapi(), $creds->getSapi()
            );

            $resp = $http->post(
                $creds->getHost() . '/api/v0/encryption/key',
                json_encode(
                    array(
                        'uses' => 1
                    )
                ),
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
            $cache = $this->cacheKey($creds, $dataset, $cache, $nocache);
        }

        ubiq_debug($creds, 'Finished getEncryptionKey for ' . $dataset->name);

        return $cache;
    }

    public function getDecryptionKey(
        Credentials $creds = NULL,
        $dataset = NULL,
        $key_headers = []
    )
    {
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
                    array(
                        'encrypted_data_key' => base64_encode($key_headers['key_enc'])
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
     * Construct the keycache object
     */
    public function __construct()
    {
    }

    /**
     * Destruct the keycache object
     */
    public function __destruct()
    {
    }
}
