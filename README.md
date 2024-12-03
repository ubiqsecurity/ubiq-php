# Ubiq Security PHP Library

The Ubiq Security PHP Library provides convenient interaction with the Ubiq
Security Platform API from applications written in PHP. It includes a
pre-defined set of functions and classes that will provide simple interfaces
to encrypt and decrypt data.

## Documentation
See the [PHP API docs](https://dev.ubiqsecurity.com/docs/api)
and [below](#usage) for examples.

Individual interfaces are documented in greater detail in the source code

Tests covered by
```
    vendor/bin/phpcs --standard=phpcsruleset.xml src/ tests/
    vendor/bin/phpunit --configuration phpunit.xml
```

## Installation

On Debian and Debian-like Linux systems:
```sh
$ sudo apt install php php-xml php-curl composer
```

### Clone the PHP repository, and install dependencies

```sh
$ git clone https://gitlab.com/ubiqsecurity/ubiq-php.git
$ cd ubiq-php
$ composer install
```

Then include the library in your code with
```
require '/path/to/Ubiq.php';
```

### Add repository and require to composer.json

```
"repositories": {
    "ubiq-php": {
        "type": "git",
        "url": "https://gitlab.com/ubiqsecurity/ubiq-php.git"
    }
}

"require": {
    "ubiqsecurity/ubiq-php":"dev-master"
}
```

### Requirements

The library has been tested with PHP 7.4.9 and 8.2.12

#### Using PHP 7.4

PHP 7.4 may require an update to the client root certs that ship with PHP to support Ubiq's SSL cert chain.

#### XDebug

XDebug is used in our development cycle to provide statistics about code coverage and assist in debugging.  XDebug has a considerable impact to performance for structured data encryption - observed at almost a 10x slower runtime than without XDebug running.

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


### Encrypt and Decrypt with Reuse

To re-use an encryption key with an unstructured dataset, use the optional `multiple_uses` parameter of the \encrypt method.

```php

$credentials = new Ubiq\Credentials();
$dataset_name = 'Filestore';

$plaintext = file_get_contents('somefile.txt');

// encrypt calls will get a unique key every time
$ciphertext_unique = \Ubiq\encrypt($credentials, $plaintext);
$ciphertext_unique2 = \Ubiq\encrypt($credentials, $plaintext);

// encrypt and use the same data key for each encryption
for ($i = 0; $i < 100; $i++) {
    $ciphertext = \Ubiq\encrypt($credentials, $plaintext, null, true);
}
```

## Ubiq Structured Encryption

This library incorporates Ubiq Structured Encryption.

### Requirements

-   Please follow the same requirements as described above for the non-structured functionality.

### Usage

You will need to obtain account credentials in the same way as described above for conventional encryption/decryption. When
you do this in your [Ubiq Dashboard][dashboard] [credentials][credentials], you'll need to enable access to structured datasets.
The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).


### Caching

When performing encryption/decryption, keys are retrieved from the Ubiq API. To speed up peformance and reduce the number of calls to the API, keys are stored in a cache within the Credentials object. It is recommended to reuse the credentials object instead of reinstantiating it unless necessary to maintain a faster runtime.

If desired, keys used for structured encryption can be pre-cached using the `primeKeyCache` method.  This is not used for unstructured dataset keys.

```php
$credentials = new Ubiq\Credentials();
$dataset_names = ["SSN", "FIRST_NAME", "LAST_NAME"];

\Ubiq\primeKeyCache($credentials, $dataset_names);
```

### Encrypt a social security text field
Pass credentials, the name of a structured dataset, and data into the encryption function.
The encrypted data will be returned.

```php
$credentials = new Ubiq\Credentials();
$dataset_name = "SSN";
$plaintext = "123-45-6789";

$ciphertext = \Ubiq\encrypt($credentials, $plaintext, $dataset_name);
        
echo 'ENCRYPTED ciphertext= ' + $ciphertext + '\n';
```

### Decrypt a social security text field
Pass credentials, the name of a structured dataset, and data into the decryption function.
The decrypted data will be returned.

```php
$credentials = new Ubiq\Credentials();
$dataset_name = "SSN";
$ciphertext = "300-0E-274t";

$plaintext = \Ubiq\decrypt($credentials, $ciphertext, $dataset_name);
        
echo 'DECRYPTED plaintext= ' + $plaintext + '\n';
```
        
Additional information on how to use these models in your own applications is available by contacting Ubiq.

### Custom Metadata for Usage Reporting
There are cases where a developer would like to attach metadata to usage information reported by the application.  Both the structured and unstructured interfaces allow user_defined metadata to be sent with the usage information reported by the libraries.

The **addReportingUserDefinedMetadata** function accepts a string in JSON format that will be stored in the database with the usage records.  The string must be less than 1024 characters and be a valid JSON format.  The string must include both the `{` and `}` symbols.  The supplied value will be used until the object goes out of scope.  Due to asynchronous processing, changing the value may be immediately reflected in subsequent usage.

The **clearReportingUserDefinedMetadata** function can be used to remove metadata that will be reported on subsequent event reporting calls.

Metadata is added at the time the events are reported.  If your event reporting configuration allows for queuing of events, be aware of managing the events in the queue vs. the metadata that will be added when the queue is flushed.

Examples are shown below.
```php

    $user_data = [
        'some_key' => 'some_value';
    ];

    $credentials = new Ubiq\Credentials();
    $credentials->addReportingUserDefinedMetadata(json_encode($user_data));

    $dataset_name = "SSN";
    $plaintext = "123-45-6789";

    \Ubiq\encrypt($credentials, $plaintext, $dataset_name);

```


### Encrypt For Search

The same plaintext data will result in different cipher text when encrypted using different data keys. The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys. This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```php

$credentials = new Ubiq\Credentials();
$dataset_name = 'SSN'; // or SSN,PHONE or ['SSN', 'PHONE']

$plaintext = '123-45-6789';

$ciphertext_array = \Ubiq\encryptForSearch($credentials, $dataset_name, $plaintext)
```


### Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  

The library can use a `ubiq-config.json` file to configure behavior and settings.  This file can be located in any of the following paths and will load the first one that is found.  A sample config file ships with the library:

* `docroot`
* parent of `docroot`
* root of `/src` where the library is installed
* parent of `/src` where the library is installed


#### Event Reporting
The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>destroy_report_async</b> Whether or not a final usage report will be sent when the library is destroyed (when PHP script exits) (default: true)
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server.
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application
- <b>timestamp_granularity</b> indicates the how granular the timestamp will be when reporting events.  Valid values are
  - "MICROS"  
    // DEFAULT: values are reported down to the microsecond resolution when possible
  - "MILLIS"  
  // values are reported to the millisecond
  - "SECONDS"  
  // values are reported to the second
  - "MINUTES"  
  // values are reported to minute
  - "HOURS"  
  // values are reported to hour
  - "HALF_DAYS"  
  // values are reported to half day
  - "DAYS"  
  // values are reported to the day

#### Key Caching
The <b>key_caching</b> section contains values to control how and when keys are cached.

- <b>unstructured</b> indicates whether keys will be cached when doing unstructured decryption. (default: true)
- <b>unstructured</b> indicates whether keys will be cached when doing structured decryption. (default: true)
- <b>encrypt</b> indicates if keys should be stored encrypted. If keys are encrypted, they will be harder to access via memory, but require them to be decrypted with each use. (default: false)
- <b>ttl_seconds</b> how many seconds before cache entries should expire and be re-retrieved (default: 1800)

#### Logging
The <b>logging</b> section contains values to control logging levels.

- <b>verbose</b> enables and disables logging output like event processing and caching.


```json
{
    "logging": {
        "verbose": true
    },
    "event_reporting": {
        "minimum_count": 5,
        "flush_interval": 2,
        "trap_exceptions": false,
        "timestamp_granularity": "SECONDS",
        "destroy_report_async": false
    },
    "key_caching" : {
        "unstructured": true,
        "structured": true,
        "encrypt": false,
        "ttl_seconds" : 1800
    }
}
```

## Ubiq API Error Reference
Occasionally, you may encounter issues when interacting with the Ubiq API. 

| Status Code | Meaning | Solution |
|---|---|---|
| 400 | Bad Request | Check name of datasets and credentials are complete. |
| 401 | Authentication issue | Check you have the correct API keys, and it has access to the datasets you are using.  Check dataset name. |
| 426 | Upgrade Required | You are using an out of date version of the library, or are trying to use newer features not supported by the library you are using.  Update the library and try again.
| 429 | Rate Limited | You are performing operations too quickly. Either slow down, or contact support@ubiqsecurity.com to increase your limits. | 
| 500 | Internal Server Error | Something went wrong. Contact support if this persists.  | 
| 504 | Internal Error | Possible API key issue.  Check credentials or contact support.  | 
