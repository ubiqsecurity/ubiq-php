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
 * Public object to manage dataset actions
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class DatasetManager
{
    const DATASET_TYPE_STRUCTURED = 'structured';
    const DATASET_TYPE_UNSTRUCTURED = 'unstructured';

    /**
     * Get a dataset as a Dataset object, with retrieving config if needed
     * Will convert to a Dataset object
     *
     * @param Credentials $creds    Credentials object to operate on
     * @param var         $dataset_name Dataset or string name of dataset
     * 
     * @return Dataset of dataset
     */
    public function getDataset(
        Credentials $creds = null,
        $dataset
    ) {
        if (Dataset::isDataset($dataset)) {
            return $dataset;
        }

        ubiq_debug($creds, 'Starting getDatasetConfig for ' . $dataset);

        if (!$creds) {
            throw new \Exception(
                'No valid credentials'
            );
            
            return;
        }

        $cache = $creds::$cachemanager::get(
            CacheManager::CACHE_TYPE_DATASET_CONFIGS, $dataset
        );
        
        if (!empty($cache)) {
            ubiq_debug($creds, 'Found dataset config cached for ' . $dataset);

            return $cache;
        }

        $dataset = new Dataset($dataset);

        $cache = $this->getDatasetConfig($creds, $dataset);
        
        ubiq_debug($creds, 'Caching dataset config for ' . $dataset->name);

        $creds::$cachemanager::set(
            CacheManager::CACHE_TYPE_DATASET_CONFIGS, $dataset->name, $dataset
        );

        return $dataset;
    }
    
    /**
     * Get a dataset configuration
     * Will get a default key if available
     * Will cache if appropriate
     *
     * @param Credentials $creds    Credentials object to operate on
     * @param Dataset     $dataset  Dataset to get a key for
     * @param bool        $no_cache Force no-cache
     * 
     * @return Array of key data
     */
    public function getDatasetConfig(
        Credentials $creds = null,
        Dataset $dataset = null
    ) {

        // if we didn't get a dataset name, we assume its unstructured
        if (empty($dataset->name)) {
            ubiq_debug($creds, 'Assume dataset config from blank dataset name');

            $dataset->type = DatasetManager::DATASET_TYPE_UNSTRUCTURED;

            return $dataset;
        }
        
        ubiq_debug($creds, 'Getting dataset config from backend for ' . $dataset->name);

        $http = new Request(
            $creds->getPapi(), $creds->getSapi()
        );

        // future support for named unstructured datasets
        // call some common endpoint that gives us dataset config for
        // structured AND unstructured and set the type based in its response

        $resp = $http->get(
            $creds->getHost() . '/api/v0/ffs?papi=' . urlencode($creds->getPapi()) . '&ffs_name=' . urlencode($dataset->name),
            'application/json'
        );

        if (!$resp['success']) {
            throw new \Exception(
                'Dataset name is invalid or could not be found ' . $resp['status']
            );

            return;
        }
        $dataset->setStructuredConfig(json_decode($resp['content'], true));

        $dataset->type = DatasetManager::DATASET_TYPE_STRUCTURED;

        return $dataset;
    }

    /**
     * Construct the datasetmanager object
     */
    public function __construct()
    {
    }

    /**
     * Destruct the datasetmanager object
     */
    public function __destruct()
    {
    }
}
