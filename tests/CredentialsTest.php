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
 * Test cases for Ubiq\Credentials
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 *
 * @covers Ubiq\_Credentials
 * @covers Ubiq\Credentials
 */
final class CredentialsTest extends TestCase
{
    /**
     * Test that a Credentials object can be successfully default-constructed
     *
     * The resulting object may or may not be ->complete()
     *
     * @return None
     */
    public function testDefaultConstruction()
    {
        $this->assertInstanceOf(
            Ubiq\Credentials::class,
            new Ubiq\Credentials()
        );
    }

    /**
     * Test that the "default" profile is loaded from a credentials file
     *
     * @return None
     */
    public function testDefaultCredentials()
    {
        $creds = new Ubiq\Credentials();
        $creds->load('tests/resources/credentials');

        $this->assertTrue($creds->complete());

        $this->assertSame(
            $creds->getPapi(), 'default_access_key_id'
        );

        $this->assertSame(
            $creds->getSapi(), 'default_secret_signing_key'
        );

        $this->assertSame(
            $creds->getSrsa(), 'default_secret_crypto_access_key'
        );

        // default server not specified by file, specified by code
        $this->assertSame(
            $creds->getHost(), 'https://api.ubiqsecurity.com'
        );
    }

    /**
     * Test that credentials can be loaded from the environment
     *
     * @return None
     */
    public function testEnvironmentCredentials()
    {
        $env = getenv();

        putenv('UBIQ_ACCESS_KEY_ID=environment_access_key_id');
        putenv('UBIQ_SECRET_SIGNING_KEY=environment_secret_signing_key');
        putenv(
            'UBIQ_SECRET_CRYPTO_ACCESS_KEY=' .
            'environment_secret_crypto_access_key'
        );
        putenv('UBIQ_SERVER=environment_server');

        $creds = new Ubiq\Credentials();

        $this->assertTrue($creds->complete());

        $this->assertSame(
            $creds->getPapi(), 'environment_access_key_id'
        );

        $this->assertSame(
            $creds->getSapi(), 'environment_secret_signing_key'
        );

        $this->assertSame(
            $creds->getSrsa(), 'environment_secret_crypto_access_key'
        );

        // server was specified without protocol, https:// should be added
        $this->assertSame(
            $creds->getHost(), 'https://environment_server'
        );

        foreach (array('UBIQ_SERVER',
                       'UBIQ_SECRET_CRYPTO_ACCESS_KEY',
                       'UBIQ_SECRET_SIGNING_KEY',
                       'UBIQ_ACCESS_KEY_ID') as $name) {
            putenv(
                $name .
                (array_key_exists($name, $env) ?
                 '=' . $env[$name] : '')
            );
        }
    }

    /**
     * Test that a specific profile can be loaded  from a credentials file
     *
     * @return None
     */
    public function testTestCredentials()
    {
        $creds = new Ubiq\Credentials();
        $creds->load('tests/resources/credentials', 'test');

        $this->assertTrue($creds->complete());

        $this->assertSame(
            $creds->getPapi(), 'test_access_key_id'
        );

        $this->assertSame(
            $creds->getSapi(), 'test_secret_signing_key'
        );

        $this->assertSame(
            $creds->getSrsa(), 'test_secret_crypto_access_key'
        );

        // default server not specified by file, specified by code
        $this->assertSame(
            $creds->getHost(), 'https://api.ubiqsecurity.com'
        );
    }

    /**
     * Test the explicit load()ing of default credentials
     *
     * This test isn't very fancy, but it's necessary to exercise the
     * lines that fill in the file and/or profile names when they're
     * missing on a call to ->load().
     *
     * @return None
     */
    public function testDefaultLoad()
    {
        $default_creds = new Ubiq\Credentials();
        $loaded_creds = new Ubiq\Credentials();

        $this->assertEquals(
            $default_creds, $loaded_creds
        );

        $this->assertEquals(
            $default_creds->load(),
            $loaded_creds->load(
                Ubiq\Credentials::getDefaultFileName(), 'default'
            )
        );

        $this->assertEquals(
            $default_creds, $loaded_creds
        );
    }

    /**
     * Test the failed explicit load()ing of credentials
     *
     * @return None
     */
    public function testFailedLoad()
    {
        $this->assertFalse(
            (new Ubiq\Credentials())->load(
                'nonexistent', 'nonexistent'
            )
        );
    }
}
