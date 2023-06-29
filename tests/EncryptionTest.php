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

require_once __DIR__ . '/../src/Ubiq.php';

use PHPUnit\Framework\TestCase;
error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE | E_STRICT);

/**
 * Test cases for Ubiq\Encryption
 *
 * Note that without decryption, these tests can only confirm correctness
 * of the functions: that they return data, that the return consistent
 * amounts of data, that they raise exceptions in response to bad or
 * out-of-order execution, etc. Correctness of the data is verified by
 * decryption tests.
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 *
 * @covers Ubiq\Encryption
 * @covers Ubiq\encrypt
 *
 * @uses Ubiq\Algorithm
 * @uses Ubiq\Credentials
 * @uses Ubiq\_Credentials
 * @uses Ubiq\Request
 */
final class EncryptionTest extends TestCase
{
    /**
     * Test that an Encryption object can be successfully default-constructed
     *
     * @return None
     */
    public function testDefaultConstruction()
    {
        $this->assertInstanceOf(
            Ubiq\Encryption::class,
            new Ubiq\Encryption()
        );
    }

    /**
     * Test that a data encryption key can be obtained from the server
     *
     * @return None
     */
    public function testSimpleConstruction()
    {
        $this->assertInstanceOf(
            Ubiq\Encryption::class,
            new Ubiq\Encryption(new Ubiq\Credentials())
        );
    }

    /**
     * Test simple encryption function
     *
     * @return None
     */
    public function testSimple()
    {
        $ct = Ubiq\encrypt(new Ubiq\Credentials, 'abc');
        $this->assertIsString($ct);
        $this->assertGreaterThan(0, strlen($ct));
    }

    /**
     * Test piecewise encryption functionality
     *
     * This test verifies that encrypting the same plaintext via the
     * simple and piecewise methods returns the same amount of
     * ciphertext from both operations
     *
     * @return None
     */
    public function testPiecewise()
    {
        $enc = new Ubiq\Encryption(new Ubiq\Credentials);

        $ct  = $enc->begin();
        $ct .= $enc->update('abc');
        $ct .= $enc->end();

        $this->assertEquals(
            strlen($ct),
            strlen(Ubiq\encrypt(new Ubiq\Credentials, 'abc'))
        );
    }

    /**
     * Test incorrect server specification
     *
     * @return None
     */
    public function testBadServer()
    {
        $creds = new Ubiq\Credentials;
        $creds->set(
            $creds->getPapi(), $creds->getSapi(), $creds->getSrsa(),
            'http://localhost:65432'
        );
        $this->expectException(Exception::class);
        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
    }

    /**
     * Test bad credentials
     *
     * @return None
     */
    public function testBadCredentials()
    {
        $creds = new Ubiq\Credentials;
        $creds->set(
            $creds->getPapi(),
            substr($creds->getSapi(), 1), $creds->getSrsa(),
            $creds->getHost()
        );
        $this->expectException(Exception::class);
        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
    }

    /**
     * Test incorrect usage of the piecewise functionality
     *
     * This test verifies that an exception occurs when the begin()
     * function is called more than once without an intervening call
     * to end()
     *
     * @return None
     */
    public function testPiecewiseBeginTwice()
    {
        $enc = new Ubiq\Encryption(new Ubiq\Credentials);
        $enc->begin();
        $this->expectException(Exception::class);
        $enc->begin();
    }

    /**
     * Test incorrect usage of the piecewise functionality
     *
     * This test verifies that an exception occurs when the update()
     * function is called before the begin() function
     *
     * @return None
     */
    public function testPiecewiseUpdateBeforeBegin()
    {
        $enc = new Ubiq\Encryption(new Ubiq\Credentials);
        $this->expectException(Exception::class);
        $enc->update('abc');
    }

    /**
     * Test incorrect usage of the piecewise functionality
     *
     * This test verifies that an exception occurs when the update()
     * function is called more than once. Currently, the underlying
     * encrypt function does not support piecewise encryption, at
     * least for authenticated modes.
     *
     * @return None
     */
    public function testPiecewiseUpdateTwice()
    {
        $enc = new Ubiq\Encryption(new Ubiq\Credentials);
        $enc->begin();
        $enc->update('abc');
        $this->expectException(Exception::class);
        $enc->update('def');
    }

    /**
     * Test incorrect usage of the piecewise functionality
     *
     * This test verifies that an exception occurs when the end()
     * function is called before either begin() or update()
     *
     * @return None
     */
    public function testPiecewiseEndBeforeBegin()
    {
        $enc = new Ubiq\Encryption(new Ubiq\Credentials);
        $this->expectException(Exception::class);
        $enc->end();
    }

    /**
     * Test piecewise functionality
     *
     * This test verifies that the piecewise functionality works
     * correctly even when update() is not called. This is equivalent
     * to encrypting no data or an empty string.
     *
     * @return None
     */
    public function testPiecewiseWithoutUpdate()
    {
        $enc = new Ubiq\Encryption(new Ubiq\Credentials);

        $ct  = $enc->begin();
        $ct .= $enc->end();

        $this->assertEquals(
            strlen($ct),
            strlen(Ubiq\encrypt(new Ubiq\Credentials, ''))
        );
    }
}
