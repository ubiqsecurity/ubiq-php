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
    private static ?CredentialsConfig $_credentials_parts = null;

    public static ?KeyManager $keymanager = null;
    public static ?DatasetManager $datasetmanager = null;
    public static ?CacheManager $cachemanager = null;
    public static ?EventProcessor $eventprocessor = null;
    public static array $config = [];

    /**
     * Checks for valid credentials
     *
     * @return bool Whether or not these credentials are valid
     */
    public function viable() : bool
    {
        return $this::$_credentials_parts->viable();
    }

    /**
     * Getter for Papi
     *
     * @return string Papi
     */
    public function getPapi() : string
    {
        return $this::$_credentials_parts->papi;
    }

    /**
     * Getter for Sapi
     *
     * @return string Sapi
     */
    public function getSapi() : string
    {
        return $this::$_credentials_parts->sapi;
    }

    /**
     * Getter for Srsa
     *
     * @return string Srsa
     */
    public function getSrsa() : string
    {
        return $this::$_credentials_parts->srsa;
    }

    /**
     * Getter for host
     *
     * @return string Host
     */
    public function getHost() : string
    {
        return $this::$_credentials_parts->host;
    }

    /**
     * Call getenv, but return null instead of false when variable is missing
     *
     * @param string $name The name of the environment variable
     *
     * @return string Value of the variable or null
     */
    private static function _getenv(string $name)
        : ?string
    {
        $val = getenv($name);
        return is_bool($val) ? null : $val;
    }

    /**
     * Adds metadata to reported events that can be used for attribution/tagging when events are retrieved
     *
     * @param string $user_data A valid JSON string less than 1024 characters
     * 
     * @return None
     */
    public static function addReportingUserDefinedMetadata(string $user_data)
    {
        if (!is_string($user_data)) {
            throw new \Exception('addReportingUserDefinedMetadata only accepts string values');
        }
        self::$eventprocessor::addUserDefinedMetadata($user_data);
    }

    /**
     * Clears metadata that will be reported events
     *
     * @return None
     */
    public static function clearReportingUserDefinedMetadata()
    {
        self::$eventprocessor::clearUserDefinedMetadata();
    }

    /**
     * Get the default path of the credentials file
     *
     * @return string A string containing the path to the credentials file
     */
    public static function getDefaultFileName()
        : ?string
    {
        return __DIR__ . DIRECTORY_SEPARATOR . '.ubiq/credentials';
    }

    /**
     * Populate properties from the environment
     *
     * @return CredentialsConfig in an "anonymous" object
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
     * @return CredentialsConfig in an "anonymous" object
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
     * @return CredentialsConfig A merged set of CredentialsConfig
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
     * @return CredentialsConfig The merged credentials
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
        return $this::$_credentials_parts &&
            $this::$_credentials_parts->viable() && $this::$_credentials_parts->host;
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
        $config = new CredentialsConfig();

        $config->papi = $papi;
        $config->sapi = $sapi;
        $config->srsa = $srsa;
        $config->host = $host;

        if ($config->viable()) {
            if (!$config->host) {
                $config->host = 'https://api.ubiqsecurity.com';
            } else if (substr($config->host, 0, 7) !== 'http://'
                && substr($config->host, 0, 8) !== 'https://'
            ) {
                $config->host = 'https://' . $config->host;
            }

            $this::$_credentials_parts = $config;
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
    public function __construct($config_file = null)
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

        $config_paths = [
            getcwd() . '/',
            getcwd() . '/../',
            __DIR__ . '/../',
            __DIR__ . '/',
        ];
        
        if (!empty($config_file)) {
            $config = file_get_contents(realpath($config_file));

            ubiq_debug($this, 'Loading ubiq-config.json at ' . $config_file);
        }
        else {
            foreach ($config_paths as $path) {
                if (!empty(realpath($path . 'ubiq-config.json')) && file_exists(realpath($path . 'ubiq-config.json'))) {
                    $config = file_get_contents(realpath($path . 'ubiq-config.json'));

                    ubiq_debug($this, 'Loading ubiq-config.json at ' . $path);

                    break;
                }
            }
        }

        if (!empty($config)) {
            $config = json_decode($config, true);
        }
        else {
            $config = [];
        }

        $config['logging'] = $config['logging'] ?? [];
        $config['logging']['verbose'] = $config['logging']['verbose'] ?? false;
        $config['logging']['vverbose'] = $config['logging']['vverbose'] ?? false;
        $config['logging']['vvverbose'] = $config['logging']['vvverbose'] ?? false;

        $config['event_reporting'] = $config['event_reporting'] ?? [];
        $config['event_reporting']['minimum_count'] = $config['event_reporting']['minimum_count'] ?? 500;
        $config['event_reporting']['flush_interval'] = $config['event_reporting']['flush_interval'] ?? 2;
        $config['event_reporting']['trap_exceptions'] = $config['event_reporting']['trap_exceptions'] ?? false;
        $config['event_reporting']['timestamp_granularity'] = $config['event_reporting']['timestamp_granularity'] ?? "SECONDS";
        $config['event_reporting']['destroy_report_async'] = $config['event_reporting']['destroy_report_async'] ?? false;

        $config['key_caching'] = $config['key_caching'] ?? [];
        $config['key_caching']['unstructured'] = $config['event_reporting']['unstructured'] ?? true;
        $config['key_caching']['structured'] = $config['event_reporting']['structured'] ?? true;
        $config['key_caching']['encrypt'] = $config['event_reporting']['encrypt'] ?? false;
        $config['key_caching']['ttl_seconds'] = $config['event_reporting']['ttl_seconds'] ?? 1800;

        self::$keymanager = new \Ubiq\KeyManager();
        self::$datasetmanager = new \Ubiq\DatasetManager();
        self::$cachemanager = new \Ubiq\CacheManager();
        self::$eventprocessor = new \Ubiq\EventProcessor($this);
        self::$config = $config;
    }

    /**
     * Destruct the credentials object
     */
    public function __destruct()
    {
        // try to catch exiting
        self::$eventprocessor->process(
            $this->config['event_reporting']['destroy_report_async'] ?? false
        );
    }
}
