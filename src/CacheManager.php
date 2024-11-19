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
    const CACHE_TYPE_DATASET_CONFIGS = 'dataset_configs';

    public static $caches = [
        // indexed by datasetname - md5(base64_encode($encrypted_data_key))
        // [
        //     '_key_enc'      => DECODED encrypted data key
        //     '_key_enc_prv'  => encrypted private key (for the wrapper)
        //     '_key_raw'      => DECODED data key, encrypted (wrapped) if config'd
        //     '_session'      => encryption session
        //     '_fingerprint'  => key fingerprint
        //     '_algorithm'    => new Algorithm()
        //     '_fragment'     => ['security_model']['enable_data_fragmentation']
        // ]
        self::CACHE_TYPE_KEYS      => [],

        self::CACHE_TYPE_EVENTS    => [],

        self::CACHE_TYPE_DATASET_CONFIGS    => []

    ];

    private static $cache_ttl = [];

    /**
     * Get a cache key
     *
     * @param string $cache_type The cache type to search
     * @param string $key        The cache key to retrieve
     * 
     * @return Var of the cache or FALSE if not found
     */
    public static function get(string $cache_type, string $key)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return false;
        }

        if (array_key_exists($cache_type . $key, self::$cache_ttl) && self::$cache_ttl[$cache_type . $key] > time()) {
            return false;
        }

        return self::$caches[$cache_type][$key] ?? false;
    }

    /**
     * Get a cache key count
     *
     * @param string $cache_type The cache type to search
     * 
     * @return The number of elements in the cache
     */
    public static function getCount(string $cache_type)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return -1;
        }

        return sizeof(self::$caches[$cache_type]);
    }

    /**
     * Get a cache key list
     *
     * @param string $cache_type The cache type to get
     * 
     * @return The array of all cache elements
     */
    public static function getAll(string $cache_type)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return [];
        }

        // loop through to validate TTL on anything in the cache
        $return = [];
        foreach (self::$caches[$cache_type] as $key) {
            $item = self::get($cache_type, $key);
            
            if (!empty($item)) {
                $return[] = $item;
            }
        }

        return $return;
    }

    /**
     * Clear a cache key list
     *
     * @param string $cache_type The cache type to clear
     * 
     * @return None
     */
    public static function clearAll(string $cache_type)
    {
        foreach (self::$caches[$cache_type] as $key) {
            if (array_key_exists($cache_type . $key, self::$cache_ttl)) {
                unset(self::$cache_ttl[$cache_type . $key]);
            }
        }

        self::$caches[$cache_type] = [];
    }

    /**
     * Get reference to cache result
     *
     * @param string $cache_type The cache type to get
     * @param string $key        The key to search for
     * 
     * @return Reference to cache result
     */
    public static function getReference(string $cache_type, string $key)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            $return = false;

            return;
        }

        if (!array_key_exists($key, self::$caches[$cache_type])) {
            $return = false;

            return;
        }

        if (array_key_exists($cache_type . $key, self::$cache_ttl) && self::$cache_ttl[$cache_type . $key] > time()) {
            $return = false;
            
            return;
        }

        $return =& self::$caches[$cache_type][$key];

        return $return;
    }

    /**
     * Set a cache key/val pair
     *
     * @param string $cache_type The cache type to set
     * @param string $key        The key to set
     * @param string $val        The value to set
     * 
     */
    public static function set(string $cache_type, string $key, $val, ?int $ttl_timestamp = NULL)
    {
        if (!array_key_exists($cache_type, self::$caches)) {
            return null;
        }

        self::$caches[$cache_type][$key] = $val;
    }

    /**
     * Set the TTL for a cached type/key pair
     *
     * @param string $cache_type The cache type to set
     * @param string $key        The key to set
     * @param ?int $ttl_timestamp The timestamp when this cached item expires
     * 
     * @return None
     */
    public static function setTTL(string $cache_type, string $key, int $ttl_timestamp)
    {
        self::$cache_ttl[$cache_type . $key] = $ttl_timestamp;
    }

    /**
     * Copy a cache value to another key
     * Does not retain TTL
     *
     * @param string $cache_type The cache type to set
     * @param string $source_key The key to copy from
     * @param string $dest_key   The key to copy to
     * 
     * @return None
     */
    public static function copy(
        string $cache_type,
        string $source_key,
        string $dest_key
    ) {
        self::set($cache_type, $dest_key, self::get($cache_type, $source_key));
    }
}
