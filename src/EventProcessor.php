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
    public $action;
    public $dataset_type;
    public $key_number;

    public $count;
    public $first_call_timestamp;
    public $last_call_timestamp;

    // maps attribute names to their names when serializing
    const SERIALIZE_MAP = [
        'api_key'               => 'api_key',
        'dataset_name'          => 'datasets',
        'dataset_group_name'    => 'dataset_groups',
        'action'                => 'action',
        'dataset_type'          => 'dataset_type',
        'key_number'            => 'key_number',
    ];

    /**
     * Create an event object from an array
     *
     * @param array $event_data Data to create from
     * 
     * @return None
     */
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

    /**
     * Get a key (serialize) an event object
     *
     * @return The serialized data
     */
    public function getKey()
    {
        $string = '';
        foreach ($this->getMappedArray() as $key=>$val) {
            $string .= $key . "='" . $val . "' ";
        }
        return trim($string);
    }

    /**
     * Get a key with mapped values as an array
     *
     * @return The mapped array
     */
    public function getMappedArray($with_metadata = FALSE)
    {
        $return = [];
        foreach (self::SERIALIZE_MAP as $attribute => $key) {
            $return[$key] = $this->{$attribute};
        }

        if ($with_metadata) {
            $return['first_call_timestamp'] = (new \DateTime())->setTimestamp($this->first_call_timestamp)->format('c');
            $return['last_call_timestamp'] = (new \DateTime())->setTimestamp($this->last_call_timestamp)->format('c');
            $return['count'] = $this->count;
        }

        return $return;
    }

    /**
     * Increment an event counter
     *
     * @return None
     */
    public function increment()
    {
        $this->count++;
        $this->last_call_timestamp = time();
    }
}

/**
 * Public singleton to manage event processing
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class EventProcessor
{
    private static $_creds = null;
    private static $_last_reported = null;
    private static $_processing = false;

    const EVENT_TYPE_ENCRYPT = 'encrypt';
    const EVENT_TYPE_DECRYPT = 'decrypt';

    /**
     * Constructs this object
     * Sets credentials to this object
     *
     * @param Credentials $creds Credentials object
     * 
     * @return None
     */
    public function __construct(Credentials &$creds)
    {
        self::$_creds =& $creds;
    }

    /**
     * Adds or increments an event in cache
     *
     * @param Event $event Event to add or increment
     * 
     * @return None
     */
    public function addOrIncrement(Event $event)
    {
        $event_idx = $event->getKey();
        $cache_event = null;

        $cache_event = self::$_creds::$cachemanager::getReference(
            CacheManager::CACHE_TYPE_EVENTS,
            $event_idx
        );

        if (!empty($cache_event)) {
            $cache_event->increment();

            ubiq_debug(self::$_creds, 'Incrementing event count to '. $cache_event->count . ' for ' . $event_idx);
        } else {
            ubiq_debug(self::$_creds, 'Initiating event with count 1 for ' . $event_idx);

            self::$_creds::$cachemanager::set(CacheManager::CACHE_TYPE_EVENTS, $event_idx, $event);
        }

        if (empty(self::$_last_reported)) {
            self::$_last_reported = time();
        }

        if ($this->_shouldProcess()) {
            $this->process();
        }
    }

    /**
     * Whether or not the queue should process
     *
     * @return Bool
     */
    private function _shouldProcess()
    {
        ubiq_debug(self::$_creds, 'Evaluating whether to process events');

        if (self::$_processing) {
            ubiq_debug(self::$_creds, 'Not processing; already running');

            return false;
        }

        if (time() - self::$_last_reported > self::$_creds->config['event_reporting']['flush_interval']
        ) {
            ubiq_debug(self::$_creds, 'Processing; time of ' . self::$_last_reported . ' to now exceeded threshold of ' . self::$_creds->config['event_reporting']['flush_interval']);

            return true;
        }
        ubiq_debug(self::$_creds, 'Not processing; time of ' . self::$_last_reported . ' to now has not exceeded threshold of ' . self::$_creds->config['event_reporting']['flush_interval']);

        if (self::$_creds::$cachemanager::getCount(CacheManager::CACHE_TYPE_EVENTS) > self::$_creds->config['event_reporting']['minimum_count']
        ) {
            ubiq_debug(self::$_creds, 'Processing; count of ' . self::$_creds::$cachemanager::getCount(CacheManager::CACHE_TYPE_EVENTS) . ' exceeded threshold of ' . self::$_creds->config['event_reporting']['minimum_count']);

            return true;
        }

        ubiq_debug(self::$_creds, 'Not processing; count of ' . self::$_creds::$cachemanager::getCount(CacheManager::CACHE_TYPE_EVENTS) . ' has not exceeded threshold of ' . self::$_creds->config['event_reporting']['minimum_count']);

        return false;
    }

    /**
     * Whether or not the queue should process
     *
     * @param Bool $async If the process should submit async or not
     * 
     * @return None
     */
    public function process(bool $async = true)
    {

        if (self::$_processing) {
            ubiq_debug(self::$_creds, 'Not processing; already running');

            return false;
        }
        
        ubiq_debug(self::$_creds, 'Processing events ' . ($async ? 'asyncronously' : 'syncronously'));

        $cached_events = self::$_creds::$cachemanager::getAll(CacheManager::CACHE_TYPE_EVENTS);
        self::$_creds::$cachemanager::clearAll(CacheManager::CACHE_TYPE_EVENTS);

        // format for reporting
        $events = [];
        foreach ($cached_events as $cached_event) {
            $event = $cached_event->getMappedArray(true);

            $event['product'] = \Ubiq\LIBRARY;
            $event['product_version'] = \Ubiq\VERSION;
            $event['user-agent'] = \Ubiq\LIBRARY . '/' . \Ubiq\VERSION;
            $event['api_version'] = \Ubiq\API_VERSION;

            $events[] = $event;
        }
        $events = ['usage' => $events];

        if (empty($events['usage'])) {
            ubiq_debug(self::$_creds, 'Not processing; no events to process');

            return false;
        }

        // in case it takes longer than 2sec to process
        // avoid concurrent reporting
        self::$_processing = true;


        $http = new Request(
            self::$_creds->getPapi(),
            self::$_creds->getSapi()
        );

        if ($async) {
            $resp = $http->postAsync(
                self::$_creds->getHost() . '/api/v3/tracking/events',
                json_encode($events),
                'application/json'
            );
        } else {
            $resp = $http->post(
                self::$_creds->getHost() . '/api/v3/tracking/events',
                json_encode($events),
                'application/json'
            );
        }

        ubiq_debug(self::$_creds, 'Processed ' . sizeof($events['usage']) . ' events');

        ubiq_debug(self::$_creds, 'Clearing events and setting last reported time');

        self::$_last_reported = time();
        self::$_processing = false;
    }
}
