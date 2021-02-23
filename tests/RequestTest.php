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
 * Test cases for Ubiq\Request
 *
 * These requests should work to any website, but the Request object
 * implements the Ubiq signature scheme, so all messages are signed.
 * To get the most out of the tests, URL's should be endpoints that
 * require a correct signature for successful results
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 *
 * @covers Ubiq\Request
 *
 * @uses Ubiq\_Credentials
 * @uses Ubiq\Credentials
 */
final class RequestTest extends TestCase
{
    /**
     * Test that a Request object can be successfully default-constructed
     *
     * @return None
     */
    public function testDefaultConstruction()
    {
        $this->assertInstanceOf(
            Ubiq\Request::class,
            new Ubiq\Request()
        );
    }

    /**
     * Test that a Request object can successfully perform a GET
     *
     * @return None
     */
    public function testUnauthenticatedGet()
    {
        $req = new Ubiq\Request();
        $res = $req->get('https://www.ubiqsecurity.com/');
        if (is_array($res)) {
            $this->assertArrayHasKey('status', $res);
            $this->assertEquals($res['status'], 200);
            $this->assertArrayHasKey('content_type', $res);
            $this->assertStringStartsWith(
                'text/html', $res['content_type']
            );
            $this->assertArrayHasKey('content', $res);
        } else {
            $this->assertIsBool($res);
            $this->assertFalse($res);
        }
    }

    /**
     * Test that a Request object can successfully perform a GET
     *
     * @return None
     */
    public function testAuthenticatedGet()
    {
        $creds = new Ubiq\Credentials();
        $req = new Ubiq\Request($creds->getPapi(), $creds->getSapi());
        /*
         * trailing slash explicitly missing and query added
         * for code coverage purposes
         */
        $res = $req->get('https://www.ubiqsecurity.com?x=y');
        if (is_array($res)) {
            $this->assertArrayHasKey('status', $res);
            $this->assertEquals($res['status'], 200);
            $this->assertArrayHasKey('content_type', $res);
            $this->assertStringStartsWith(
                'text/html', $res['content_type']
            );
            $this->assertArrayHasKey('content', $res);
        } else {
            $this->assertIsBool($res);
            $this->assertFalse($res);
        }
    }

    /**
     * Test that a Request object can successfully perform a POST
     *
     * @return None
     */
    public function testPost()
    {
        $creds = new Ubiq\Credentials();
        $req = new Ubiq\Request($creds->getPapi(), $creds->getSapi());
        $res = $req->post(
            $creds->getHost() . '/api/v0/encryption/key',
            'null', 'application/json'
        );
        if (is_array($res)) {
            $this->assertArrayHasKey('status', $res);
            $this->assertEquals($res['status'], 200);
            $this->assertArrayHasKey('content_type', $res);
            $this->assertStringStartsWith(
                'application/json', $res['content_type']
            );
            $this->assertArrayHasKey('content', $res);
            $this->assertEquals($res['content'], 'null');
        } else {
            $this->assertIsBool($res);
            $this->assertFalse($res);
        }
    }

    /**
     * Test that a Request object can successfully perform a POST
     *
     * @return None
     */
    public function testPatch()
    {
        $creds = new Ubiq\Credentials();
        $req = new Ubiq\Request($creds->getPapi(), $creds->getSapi());
        $res = $req->patch(
            $creds->getHost() . '/api/v0/encryption/key',
            'null', 'application/json'
        );

        /*
         * sending the patch request to the wrong endpoint
         * should result in a 404 (not found)
         */
        if (is_array($res)) {
            $this->assertArrayHasKey('status', $res);
            $this->assertEquals($res['status'], 404);
            $this->assertArrayHasKey('content_type', $res);
            $this->assertStringStartsWith(
                'text/html', $res['content_type']
            );
            $this->assertArrayHasKey('content', $res);
            $this->assertEquals($res['content'], '');
        } else {
            $this->assertIsBool($res);
            $this->assertFalse($res);
        }
    }
}
