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
 * Object used to store a set of credentials while loading
 * Not used outside of Credentials
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class CredentialsConfig
{
    public $papi = null;
    public $sapi = null;
    public $srsa = null;
    public $host = null;
    public $config = null;

    /**
     * Determine if enough of the credentials properties are present to
     * make a complete set
     *
     * @return bool
     */
    public function viable()
        : bool
    {
        return $this->papi && $this->sapi && $this->srsa;
    }
};

/**
 * Public object in which to store Ubiq credentials
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class Credentials
{
    private /*CredentialsConfig*/ $_creds = null;

    public static $keymanager = null;
    public static $cachemanager = null;
    public static $eventprocessor = null;

    /**
     * Getter for Papi
     *
     * @return Papi
     */
    public function getPapi() : string
    {
        return $this->_creds->papi;
    }

    /**
     * Getter for Sapi
     *
     * @return Sapi
     */
    public function getSapi() : string
    {
        return $this->_creds->sapi;
    }

    /**
     * Getter for Srsa
     *
     * @return Srsa
     */
    public function getSrsa() : string
    {
        return $this->_creds->srsa;
    }

    /**
     * Getter for host
     *
     * @return Host
     */
    public function getHost() : string
    {
        return $this->_creds->host;
    }

    /**
     * Call getenv, but return null instead of false when variable is missing
     *
     * @param string $name The name of the environment variable
     *
     * @return Value of the variable or null
     */
    private static function _getenv(string $name)
        : ?string
    {
        $val = getenv($name);
        return is_bool($val) ? null : $val;
    }

    /**
     * Get the default path of the credentials file
     *
     * @return A string containing the path to the credentials file
     */
    public static function getDefaultFileName()
        : ?string
    {
        return __DIR__ . DIRECTORY_SEPARATOR . '.ubiq/credentials';
    }

    /**
     * Populate properties from the environment
     *
     * @return Credentials in an "anonymous" object
     */
    private static function _loadEnvironment()
        : CredentialsConfig
    {
        $creds = new CredentialsConfig();

        $creds->papi = Credentials::_getenv('UBIQ_ACCESS_KEY_ID');
        $creds->sapi = Credentials::_getenv('UBIQ_SECRET_SIGNING_KEY');
        $creds->srsa = Credentials::_getenv('UBIQ_SECRET_CRYPTO_ACCESS_KEY');
        $creds->host = Credentials::_getenv('UBIQ_SERVER');

        return $creds;
    }

    /**
     * Populate properties from profile in credentials file.
     *
     * @param string $filename The path to the credentials file
     * @param string $profname The name of the profile in the credentials
     *
     * @return Credentials in an "anonymous" object
     */
    private static function _loadFile(string $filename, string $profname)
        : CredentialsConfig
    {
        $creds = new CredentialsConfig();

        $content = false;
        if (file_exists($filename)) {
            $content = parse_ini_file($filename, true);
        }

        if ($content) {
            if (array_key_exists($profname, $content)) {
                $profile = &$content[$profname];

                $set = function (&$r, &$profile, $key) {
                    if (array_key_exists($key, $profile)) {
                        $r = $profile[$key];
                    }
                };

                $set($creds->papi, $profile, 'ACCESS_KEY_ID');
                $set($creds->sapi, $profile, 'SECRET_SIGNING_KEY');
                $set($creds->srsa, $profile, 'SECRET_CRYPTO_ACCESS_KEY');
                $set($creds->host, $profile, 'SERVER');
            }
        }

        return $creds;
    }

    /**
     * Merge credential properties in $a and $b, using $a when both are present
     *
     * @param CredentialsConfig $a The first set of credentials
     * @param CredentialsConfig $b The second set of credentials
     *
     * @return A merged set of CredentialsConfig
     */
    private static function _merge(CredentialsConfig $a, CredentialsConfig $b)
        : CredentialsConfig
    {
        $creds = new CredentialsConfig();

        $set = function (&$r, $a , $b) {
            $r = $a;
            if (!$r) {
                $r = $b;
            }
        };

        $set($creds->papi, $a->papi, $b->papi);
        $set($creds->sapi, $a->sapi, $b->sapi);
        $set($creds->srsa, $a->srsa, $b->srsa);
        $set($creds->host, $a->host, $b->host);

        return $creds;
    }

    /**
     * Merge a given set of credentials with the "default" credentials
     * from a given file
     *
     * @param CredentialsConfig $creds    A set of credentials to merge with
     * @param string            $filename The path to the credentials file
     *
     * @return The merged credentials
     */
    private static function _mergeWithDefault(
        CredentialsConfig $creds,
        string $filename
    ) : CredentialsConfig {
        if (!$creds->viable()) {
            $creds = Credentials::_merge(
                $creds, Credentials::_loadFile($filename, 'default')
            );
        }

        return $creds;
    }

    /**
     * Determine if all properties are present in the credentials
     *
     * @return bool
     */
    public function complete()
        : bool
    {
        return $this->_creds &&
            $this->_creds->viable() && $this->_creds->host;
    }

    /**
     * Explicitly set the credentials
     *
     * @param string $papi The access key id
     * @param string $sapi The secret signing key
     * @param string $srsa The secret crypto access key
     * @param string $host The name of the host to connect to
     *
     * @return bool
     */
    public function set(
        string $papi, string $sapi, string $srsa,
        ?string $host = null
    ) : bool {
        $creds = new CredentialsConfig();

        $creds->papi = $papi;
        $creds->sapi = $sapi;
        $creds->srsa = $srsa;
        $creds->host = $host;

        if ($creds->viable()) {
            if (!$creds->host) {
                $creds->host = 'https://api.ubiqsecurity.com';
            } else if (substr($creds->host, 0, 7) !== 'http://'
                && substr($creds->host, 0, 8) !== 'https://'
            ) {
                $creds->host = 'https://' . $creds->host;
            }

            $this->_creds = $creds;
        }

        return $this->complete();
    }

    /**
     * Load the credentials from a file
     *
     * @param string $filename The path to the credentials file
     * @param string $profname The name of the profile
     *
     * @return None
     */
    public function load(?string $filename = null, ?string $profname = null)
        : bool
    {
        if (!$filename) {
            $filename = Credentials::getDefaultFileName();
        }
        if (!$profname) {
            $profname = 'default';
        }

        $creds = Credentials::_mergeWithDefault(
            Credentials::_loadFile($filename, $profname), $filename
        );

        $res = $creds->viable();
        if ($res) {
            $res = $this->set(
                $creds->papi,
                $creds->sapi,
                $creds->srsa,
                $creds->host
            );
        }

        return $res;
    }

    /**
     * Construct credentials from the environment. Missing components
     * will be loaded from "default" profile in ~/.ubiq/credentials
     */
    public function __construct()
    {
        $creds = Credentials::_mergeWithDefault(
            Credentials::_loadEnvironment(),
            Credentials::getDefaultFileName()
        );

        if ($creds->viable()) {
            $this->set(
                $creds->papi,
                $creds->sapi,
                $creds->srsa,
                $creds->host
            );
        }

        $config = file_get_contents(realpath(__DIR__ . '/../ubiq-config.json'));

        if (empty($config)) {
            $creds->config = [
                'debug' => false,
                'event_reporting' => [
                    'minimum_event_count' => 5,
                    'flush_interval' => 2,
                    'destroy_report_async' => false
                ],
                'key_caching' => [
                    'unstructured'  => false,
                    'encrypt'       => false,
                ]
            ];
        } else {
            $this->config = json_decode($config, true);
        }

        self::$keymanager = new \Ubiq\KeyManager();
        self::$cachemanager = new \Ubiq\CacheManager();
        self::$eventprocessor = new \Ubiq\EventProcessor($this);
    }

    /**
     * Destruct the credentials object
     */
    public function __destruct()
    {
        // try to catch exiting
        $this->eventprocessor->process(
            $this->config['event_reporting']['destroy_report_async'] ?? false
        );
    }
}
