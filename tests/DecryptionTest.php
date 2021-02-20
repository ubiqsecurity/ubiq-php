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
 * Test cases for Ubiq\Decryption
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 *
 * @covers Ubiq\Decryption
 * @covers Ubiq\decrypt
 *
 * @uses Ubiq\Algorithm
 * @uses Ubiq\Credentials
 * @uses Ubiq\_Credentials
 * @uses Ubiq\Encryption
 * @uses Ubiq\Request
 * @uses Ubiq\encrypt
 */
final class DecryptionTest extends TestCase
{
    const PLAINTEXT = 'abc';

    /**
     * Test that a Decryption object can be successfully default-constructed
     *
     * @return None
     */
    public function testDefaultConstruction()
    {
        $this->assertInstanceOf(
            Ubiq\Decryption::class,
            new Ubiq\Decryption()
        );
    }

    /**
     * Test that a Decryption object can be successfully
     * constructed with credentials
     *
     * @return None
     */
    public function testSimpleConstruction()
    {
        $this->assertInstanceOf(
            Ubiq\Decryption::class,
            new Ubiq\Decryption(new Ubiq\Credentials())
        );
    }

    /**
     * Test simple decryption function
     *
     * @return None
     */
    public function testSimple()
    {
        $creds = new Ubiq\Credentials;

        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
        $pt = Ubiq\decrypt($creds, $ct);

        $this->assertEquals($pt, DecryptionTest::PLAINTEXT);
    }

    /**
     * Test piecewise decryption functionality
     *
     * @return None
     */
    public function testPiecewise()
    {
        $creds = new Ubiq\Credentials;

        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);

        $dec = new Ubiq\Decryption($creds);

        $pt  = $dec->begin();
        $pt .= $dec->update($ct);
        $pt .= $dec->end();

        $this->assertEquals($pt, DecryptionTest::PLAINTEXT);
    }

    /**
     * Test incorrect server specification
     *
     * @return None
     */
    public function testBadServer()
    {
        $creds = new Ubiq\Credentials;
        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
        $creds->set(
            $creds->getPapi(), $creds->getSapi(), $creds->getSrsa(),
            'http://localhost:65432'
        );
        $this->expectException(Exception::class);
        $pt = Ubiq\decrypt($creds, $ct);
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
        $dec = new Ubiq\Decryption(new Ubiq\Credentials);
        $dec->begin();
        $this->expectException(Exception::class);
        $dec->begin();
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
        $creds = new Ubiq\Credentials;

        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);

        $dec = new Ubiq\Decryption($creds);
        $this->expectException(Exception::class);
        $dec->update($ct);
    }

    /**
     * Test incorrect usage of the piecewise functionality
     *
     * This test verifies that an exception occurs when the update()
     * function is called more than once. Currently, the underlying
     * decrypt function does not support piecewise decryption, at
     * least for authenticated modes.
     *
     * @return None
     */
    public function testPiecewiseUpdateTwice()
    {
        $creds = new Ubiq\Credentials;

        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);

        $dec = new Ubiq\Decryption($creds);
        $dec->begin();
        $dec->update($ct);
        $this->expectException(Exception::class);
        $dec->update('dummy data');
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
        $dec = new Ubiq\Decryption(new Ubiq\Credentials);
        $this->expectException(Exception::class);
        $dec->end();
    }

    /**
     * Test piecewise functionality
     *
     * This test verifies that the piecewise functionality works
     * correctly even when update() is not called.
     *
     * @return None
     */
    public function testPiecewiseWithoutUpdate()
    {
        $dec = new Ubiq\Decryption(new Ubiq\Credentials);

        $pt  = $dec->begin();
        $pt .= $dec->end();

        $this->assertEquals($pt, '');
    }

    /**
     * Test bad version field in the header
     *
     * @return None
     */
    public function testBadHeaderVersion()
    {
        $creds = new Ubiq\Credentials;
        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
        /* make sure ct decrypts normally */
        $pt = Ubiq\decrypt($creds, $ct);
        /*
         * replace the version with a
         * different, unsupported value
         */
        $ct = pack('C', 0xff) . substr($ct, 1);
        $this->expectException(Exception::class);
        $pt = Ubiq\decrypt($creds, $ct);
    }

    /**
     * Test corrupted key
     *
     * @return None
     */
    public function testCorruptedKey()
    {
        $creds = new Ubiq\Credentials;
        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
        /* remove a byte from the encrypted key */
        $ct = substr($ct, 0, 200) . substr($ct, 201);
        $this->expectException(Exception::class);
        $pt = Ubiq\decrypt($creds, $ct);
    }

    /**
     * Test short header/ciphertext
     *
     * @return None
     */
    public function testShortHeader()
    {
        $creds = new Ubiq\Credentials;
        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
        /* make sure ct decrypts normally */
        $pt = Ubiq\decrypt($creds, $ct);
        /*
         * the header is several hundred bytes;
         * chop a bunch of them off
         */
        $ct = substr($ct, 0, 200);
        $this->expectException(Exception::class);
        $pt = Ubiq\decrypt($creds, $ct);
    }

    /**
     * Test if corrupted cipher text can be detected
     *
     * This test can be improved/made more exact/explicit if the
     * exact boundaries of where the ciphertext and the tags are,
     * but those aren't readily available at this level. In
     * addition, since the algorithm is not readily available,
     * the test can't determine if an authenticated algorithm is
     * in use. This test may fail for unauthenticated algorithms.
     *
     * @return None
     */
    public function testCorruptedCiphertext()
    {
        $creds = new Ubiq\Credentials;
        $ct = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
        /* just chop off the last byte */
        $ct = substr($ct, 0, -1);
        $this->expectException(Exception::class);
        $pt = Ubiq\decrypt($creds, $ct);
    }

    /**
     * Test that a decryption object can be reused
     * with different data keys
     *
     * @return None
     */
    public function testObjectReuse()
    {
        $creds = new Ubiq\Credentials;
        $ct1 = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);
        $ct2 = Ubiq\encrypt($creds, DecryptionTest::PLAINTEXT);

        $dec = new Ubiq\Decryption($creds);

        $pt1  = $dec->begin();
        $pt1 .= $dec->update($ct1);
        $pt1 .= $dec->end();
        $this->assertEquals($pt1, DecryptionTest::PLAINTEXT);

        $pt2  = $dec->begin();
        $pt2 .= $dec->update($ct2);
        $pt2 .= $dec->end();
        $this->assertEquals($pt2, DecryptionTest::PLAINTEXT);
    }
}
