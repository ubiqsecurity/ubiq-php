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
 * Ubiq Algorithm object
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class Algorithm
{
    const AES_256_GCM = 0;
    const AES_128_GCM = 1;
    const FF1 = 2;

    public $id, $name;
    public $keylen, $ivlen, $taglen;

    /**
     * Add algorithm parameters to an array
     *
     * The array is indexed by both the $id and by $name. Each entry
     * contains the $id, $name, $keylen, $ivlen, and $taglen in that order.
     *
     * @param array  $algos  The array to which to append the new entries
     * @param int    $id     The numeric id of the algorithm
     * @param string $name   A human readable string identifying the algorithm
     * @param int    $keylen The length of the algorithm's key, in bytes
     * @param int    $ivlen  The length of the initialization vector, in bytes
     * @param int    $taglen The length of the authentication tag, if any,
     *                       in bytes
     *
     * @return None
     */
    private static function _add(
        array &$algos,
        int $id, string $name,
        int $keylen, int $ivlen, int $taglen
    ) : void {
        $algos += array_fill_keys(
            array($id, $name),
            array($id, $name, $keylen, $ivlen, $taglen)
        );
    }

    /**
     * Construct an Algorithm object
     *
     * @param mixed $ident An integer or string identifying the algorithm
     *
     * @return None
     */
    public function __construct(/* int|string */ $ident = null)
    {
        if (!is_null($ident)) {
            $algos = [];
            Algorithm::_add(
                $algos, Algorithm::AES_256_GCM, 'aes-256-gcm', 32, 12, 16
            );
            Algorithm::_add(
                $algos, Algorithm::AES_128_GCM, 'aes-128-gcm', 16, 12, 16
            );
            Algorithm::_add(
                $algos, Algorithm::FF1, 'ff1', 16, 12, 16
            );

            if (!array_key_exists($ident, $algos)) {
                throw new \Exception(
                    'Algorithm not supported'
                );
            }

            $algo = $algos[$ident];

            $this->id       = array_shift($algo);
            $this->name     = array_shift($algo);
            $this->keylen   = array_shift($algo);
            $this->ivlen    = array_shift($algo);
            $this->taglen   = array_shift($algo);
        }
    }
}
