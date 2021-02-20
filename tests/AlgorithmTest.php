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

use PHPUnit\Framework\TestCase;
error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE | E_STRICT);

/**
 * Test cases for Ubiq\Algorithm
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 *
 * @covers Ubiq\Algorithm
 */
final class AlgorithmTest extends TestCase
{
    /**
     * Test that an Algorithm object can be successfully default-constructed
     *
     * @return None
     */
    public function testDefaultConstruction()
    {
        $this->assertInstanceOf(
            Ubiq\Algorithm::class,
            new Ubiq\Algorithm()
        );
    }

    /**
     * Test that an unsupported algorithm throws an exception
     *
     * @return None
     */
    public function testUnsupportedAlgorithm()
    {
        $this->expectException(Exception::class);
        new Ubiq\Algorithm('unsupported-algorithm');
    }

    /**
     * Test that the AES-256-GCM algorithm has the correct parameters
     *
     * @return None
     */
    public function testAes256Gcm()
    {
        foreach (array(Ubiq\Algorithm::AES_256_GCM,
                       'aes-256-gcm') as $ident) {
            $algo = new Ubiq\Algorithm($ident);
            $this->assertEquals($algo->id, 0);
            $this->assertEquals($algo->name, 'aes-256-gcm');
            $this->assertEquals($algo->keylen, 32);
            $this->assertEquals($algo->ivlen, 12);
            $this->assertEquals($algo->taglen, 16);
        }
    }

    /**
     * Test that the AES-128-GCM algorithm has the correct parameters
     *
     * @return None
     */
    public function testAes128Gcm()
    {
        foreach (array(Ubiq\Algorithm::AES_128_GCM,
                       'aes-128-gcm') as $ident) {
            $algo = new Ubiq\Algorithm($ident);
            $this->assertEquals($algo->id, 1);
            $this->assertEquals($algo->name, 'aes-128-gcm');
            $this->assertEquals($algo->keylen, 16);
            $this->assertEquals($algo->ivlen, 12);
            $this->assertEquals($algo->taglen, 16);
        }
    }
}
