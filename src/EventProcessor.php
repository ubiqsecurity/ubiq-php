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
 * Public object in which to store events
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class Event
{
    public $api_key;
    public $dataset_name;
    public $dataset_group_name;
    public $billing_action;
    public $dataset_type;
    public $key_number;

    public $count;
    public $first_call_timestamp;
    public $last_call_timestamp;

    public function __construct($event_data)
    {
        $this->first_call_timestamp = time();
        $this->last_call_timestamp = time();

        $this->count = 1;

        foreach ($event_data as $key => $val) {
            if (property_exists($this, $key)) {
                $this->{$key} = $val;
            }
        }
    }

    public function getKey()
    {
        return    "api_key='" . $this->api_key 
                . "' datasets='" . $this->dataset_name
                . "' billing_action='" . $this->billing_action
                . "' dataset_groups='" . $this->dataset_group_name
                . "' dataset_type='" . $this->dataset_type
                . "' key_number='" . $this->key_number . "'";
    }

    public function increment()
    {
        $this->count++;
        $this->last_call_timestamp = time();
    }
}

/**
 * Public singleton to manage event processing
 * 
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class EventProcessor
{
    protected static $_instance = NULL;
    private static $creds = NULL;
    private static $last_reported = NULL;
    private static $processing = FALSE;

    const EVENT_TYPE_ENCRYPT = 'encrypt';
    const EVENT_TYPE_DECRYPT = 'decrypt';

    public function setCredentials(&$creds)
    {
        self::$creds =& $creds;
    }

    public function addOrIncrement(Event $event)
    {
        $cache_manager = \Ubiq\CacheManager::getInstance();
        $event_idx = $event->getKey();
        $cache_event = NULL;

        $cache_manager->setToReference(CacheManager::CACHE_TYPE_EVENTS, $event_idx, $cache);

        if (!empty($cache)) {
            $cache_event->increment();

            ubiq_debug(self::$creds, 'Incrementing event count to ' . $cache_event->count . ' for ' . $event_idx);
        }
        else {
            ubiq_debug(self::$creds, 'Initiating event with count 1 for ' . $event_idx);

            $cache_manager->set(CacheManager::CACHE_TYPE_EVENTS, $event_idx, $event);
        }

        if (empty(self::$last_reported)) {
            self::$last_reported = time();
        }

        if ($this->_should_process()) {
            $this->process();
        }
    }

    private function _should_process()
    {
        ubiq_debug(self::$creds, 'Evaluating whether to process events');

        if (self::$processing) {
            ubiq_debug(self::$creds, 'Not processing; already running');

            return FALSE;
        }

        if (time() - self::$last_reported > self::$creds->config['event_reporting']['flush_interval']) {
            ubiq_debug(self::$creds, 'Processing; time of ' . self::$last_reported . ' to now exceeded threshold of ' . self::$creds->config['event_reporting']['flush_interval']);

            return TRUE;
        }
        ubiq_debug(self::$creds, 'Not processing; time of ' . self::$last_reported . ' to now has not exceeded threshold of ' . self::$creds->config['event_reporting']['flush_interval']);

        $cache_manager = \Ubiq\CacheManager::getInstance();
        if ($cache_manager->getCount(CacheManager::CACHE_TYPE_EVENTS) > self::$creds->config['event_reporting']['minimum_event_count']) {
            ubiq_debug(self::$creds, 'Processing; count of ' . $cache_manager->getCount(CacheManager::CACHE_TYPE_EVENTS) . ' exceeded threshold of ' . self::$creds->config['event_reporting']['minimum_event_count']);

            return TRUE;
        }
        ubiq_debug(self::$creds, 'Not processing; count of ' . $cache_manager->getCount(CacheManager::CACHE_TYPE_EVENTS) . ' has not exceeded threshold of ' . self::$creds->config['event_reporting']['minimum_event_count']);

        return FALSE;
    }

    public function process($async = TRUE)
    {

        if (self::$processing) {
            ubiq_debug(self::$creds, 'Not processing; already running');

            return FALSE;
        }
        
        ubiq_debug(self::$creds, 'Processing events ' . ($async ? 'asyncronously' : 'syncronously'));

        // in case it takes longer than 2sec to prothis.endpoint = `/${this.restApiV3Root}/tracking/events`;cess
        // avoid concurrent reporting
        self::$processing = TRUE;

        $cache_manager = \Ubiq\CacheManager::getInstance();

        $http = new Request(
            self::$creds->getPapi(),
            self::$creds->getSapi()
        );

        if ($async) {
            $resp = $http->postAsync(
                self::$creds->getHost() . '/api/v3/tracking/events',
                json_encode($cache_manager->getAll(CacheManager::CACHE_TYPE_EVENTS)),
                'application/json'
            );
        }
        else {
            $resp = $http->post(
                self::$creds->getHost() . '/api/v3/tracking/events',
                json_encode($cache_manager->getAll(CacheManager::CACHE_TYPE_EVENTS)),
                'application/json'
            );
        }

        ubiq_debug(self::$creds, 'Clearing events and setting last reported time');

        $cache_manager->clearAll(CacheManager::CACHE_TYPE_EVENTS);

        self::$last_reported = time();
        self::$processing = FALSE;
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
    final public static function getInstance()
    {
        if (null !== static::$_instance){
            return static::$_instance;
        }
        static::$_instance = new static();
        return static::$_instance;
    }
}
