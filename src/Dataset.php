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
class Dataset
{
    public $name;
    public $group_name;
    public $type;
    public $structured_config;

    /**
     * data_type string from the server config: "string" (default),
     * "integer", "date", "datetime", "token", etc. Convenience mirror
     * of $structured_config['data_type'].
     */
    public ?string $data_type = null;

    /**
     * Typed wrapper for $structured_config['data_type_config']. Null
     * unless the dataset has a typed data_type with bounds (integer,
     * date, datetime).
     */
    public ?DataTypeConfig $data_type_config = null;

    /**
     * Create a dataset
     *
     * @param string $dataset_name       Optional name
     * @param string $dataset_group_name Optional name
     *
     * @return None
     */
    public function __construct(
        ?string $dataset_name,
        ?string $dataset_group_name = null,
        ?string $dataset_type = null,
        ?array $structured_config = []
    ) {
        $this->name = $dataset_name ?? '';
        $this->group_name = $dataset_group_name ?? '';
        $this->type = $dataset_type;
        $this->setStructuredConfig($structured_config);
    }
    
    /**
     * Whether or not something is a dataset
     *
     * @param string $o The thing to evaluate
     * 
     * @return Bool
     */
    public static function isDataset($o)
    {
        if (empty($o)) {
            return false;
        }
        if (!is_object($o)) {
            return false;
        }
        if (get_class($o) != 'Dataset' && get_class($o) != 'Ubiq\\Dataset') {
            return false;
        }

        return true;
    }

    /**
     * Sets the structured config, including
     * sorting the passthrough rules
     *
     * @param array $config The structured config
     * 
     */
    public function setStructuredConfig(array $config)
    {
        $this->structured_config = $config;

        // sort the passthrough rules by priority
        if (!empty($this->structured_config['passthrough_rules'])) {
            usort($this->structured_config['passthrough_rules'], function ($a, $b) {
                return (intval($a['priority'] ?? 0) > intval($b['priority'] ?? 0));
            });
        }

        // Populate typed data_type / data_type_config mirrors of the
        // server-returned config so callers don't need to reach into
        // $structured_config to type-check the dataset.
        $this->data_type = isset($config['data_type']) ? (string) $config['data_type'] : null;
        $this->data_type_config = DataTypeConfig::fromArray($config['data_type_config'] ?? null);

        return $this;
    }

    public function getDataType(): ?string
    {
        return $this->data_type;
    }

    public function getDataTypeConfig(): ?DataTypeConfig
    {
        return $this->data_type_config;
    }
}
