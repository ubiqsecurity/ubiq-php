# Ubiq Security PHP Library
[![badge][pipeline-status]][gitlab-repo]
[![badge][coverage-status]][gitlab-repo]

The Ubiq Security PHP Library provides convenient interaction with the Ubiq
Security Platform API from applications written in PHP. It includes a
pre-defined set of functions and classes that will provide simple interfaces
to encrypt and decrypt data.

## Documentation
See the [PHP API docs](https://dev.ubiqsecurity.com/docs/api)
and [below](#usage) for examples.

Individual interfaces are documented in greater detail in the source code

## Installation

On Debian and Debian-like Linux systems:
```sh
$ sudo apt install php php-xml php-curl composer
```

Clone the PHP repository, and install dependencies

```sh
$ git clone https://gitlab.com/ubiqsecurity/ubiq-php.git
$ cd ubiq-php
$ composer install
```

### Requirements

The library has been tested with PHP 7.3.

To use the library in your code, simply
```php
require '/path/to/Ubiq.php';
```

## Usage

### Credentials

The library needs to be configured with your account credentials which are
available in your [Ubiq Dashboard][dashboard] [credentials][credentials]. The
credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).

#### Read credentials from a specific file and use a specific profile
```php
$credentials = new Ubiq\Credentials();
$credentials->load(
    '/path/to/credentials', 'profile-name'
);
```

#### Read credentials from ~/.ubiq/credentials and use the default profile
```php
$credentials = new Ubiq\Credentials();
```

#### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID  
UBIQ_SECRET_SIGNING_KEY  
UBIQ_SECRET_CRYPTO_ACCESS_KEY  
```php
$credentials = new Ubiq\Credentials();
```

#### Explicitly set the credentials
```php
$credentials = new Ubiq\Credentials();
$credentials->set(
    '...' /* access key id */,
    '...' /* secret signing key */,
    '...' /* secret crypto access key */,
    '...' /* Ubiq API server, may omit this parameter */
);
```

### Simple encryption and decryption

#### Encrypt a single block of data

Pass credentials and data into the encryption function. The encrypted data
will be returned.

```php
$credentials = new Ubiq\Credentials();
$ct = Ubiq\encrypt($credentials, $pt);
```

#### Decrypt a single block of data

Pass credentials and encrypted data into the decryption function. The
plaintext data will be returned.

```php
$credentials = new Ubiq\Credentials();
$pt = Ubiq\decrypt($credentials, $ct);
```

#### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed
    <br>
    *Note that repeatedly calling the update method is not currently supported by the
    underlying PHP crypto library. However, the interface is present and can be used
    in cases where the caller wishes to reuse the encryption object for multiple
    encryptions.*
- Call the encryption instance end method

```php
$credentials = new Ubiq\Credentials();
$encryption = new Ubiq\Encryption($credentials, 1);

$pt = fread($infile, $filesize);

$ct  = $encryption->begin();
$ct .= $encryption->update($pt);
$ct .= $encryption->end();
```

#### Decrypt a large data element where data is loaded in chunks

- Create an instance of the decryption object using the credentials.
- Call the decryption instance begin method
- Call the decryption instance update method repeatedly until all the data is processed
    <br>
    *Note that repeatedly calling the update method is not currently supported by the
    underlying PHP crypto library. However, the interface is present and can be used
    in cases where the caller wishes to reuse the decryption object for multiple
    decryptions.*
- Call the decryption instance end method

```php
$credentials = new Ubiq\Credentials();
$decryption = new Ubiq\Decryption($credentials, 1);

$ct = fread($infile, $filesize);

$pt  = $decryption->begin();
$pt .= $decryption->update($ct);
$pt .= $decryption->end();
```

[gitlab-repo]: https://gitlab.com/ubiqsecurity/ubiq-php/-/commits/master
[pipeline-status]: https://gitlab.com/ubiqsecurity/ubiq-php/badges/master/pipeline.svg
[coverage-status]: https://gitlab.com/ubiqsecurity/ubiq-php/badges/master/coverage.svg
[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
