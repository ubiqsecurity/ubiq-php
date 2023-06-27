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
 * Public object in which to store Ubiq cache
 * 
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class CacheManager
{
    const CACHE_TYPE_KEYS = 'keys';
    const CACHE_TYPE_EVENTS = 'events';

    protected static $_instance = NULL;
    
    public static $caches = [
        // indexed by datasetname - md5(base64_encode($encrypted_data_key))
        // [
        //     '_key_enc'      => DECODED encrypted data key
        //     '_key_enc_prv'  => encrypted private key (for the wrapper)
        //     '_key_raw'      => DECODED data key, either encrypted (wrapped) or decrypted based on config
        //     '_session'      => encryption session
        //     '_fingerprint'  => key fingerprint
        //     '_algorithm'    => new Algorithm()
        //     '_fragment'     => ['security_model']['enable_data_fragmentation']
        // ]
        self::CACHE_TYPE_KEYS      => [],

        self::CACHE_TYPE_EVENTS    => []
    ];

    public function get(string $cache_type, string $key)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return FALSE;
        }

        return self::$caches[$cache_type][$key] ?? FALSE;
    }

    public function getCount(string $cache_type)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return -1;
        }

        return sizeof(self::$caches[$cache_type]);
    }

    public function getAll(string $cache_type)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return [];
        }

        return self::$caches[$cache_type];
    }

    public function clearAll(string $cache_type)
    {
        self::$caches[$cache_type] = [];
    }

    public function setToReference(string $cache_type, string $key, &$return)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            $return = FALSE;

            return;
        }

        if (!array_key_exists($key, self::$caches[$cache_type])) {
             $return = FALSE;

            return;
        }

        $return =& self::$caches[$cache_type][$key];
    }

    public function set(string $cache_type, string $key, $val)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return NULL;
        }

        self::$caches[$cache_type][$key] = $val;
    }

    public static function copy(string $cache_type, string $source_key, string $dest_key)
    {
        echo 'copyig ' . $source_key . ' to ' . $dest_key . PHP_EOL . PHP_EOL . PHP_EOL;
        self::set($cache_type, $dest_key, self::get($cache_type, $source_key));
    }

    /**
     * Prevent direct object creation
     */
    final private function __construct() { }

    /**
     * Prevent object cloning
     */
    final private function __clone() { }

    /**
     * Returns new or existing Singleton instance
     * @return Singleton
     */
    final public static function getInstance(){
        if (null !== static::$_instance){
            return static::$_instance;
        }
        static::$_instance = new static();
        return static::$_instance;
    }
}