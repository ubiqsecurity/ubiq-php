# Ubiq Security Sample Application using PHP Library

This sample application will demonstrate how to encrypt and decrypt data using the different APIs.

### Documentation

See the [PHP API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Make sure PHP is installed on your system as described [here](/README.md#installation).

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard

<pre>
[default]
ACCESS_KEY_ID = ...  
SECRET_SIGNING_KEY = ...  
SECRET_CRYPTO_ACCESS_KEY = ...  
</pre>

## Build the examples

Clone the PHP repository, and install dependencies

```sh
$ git clone https://gitlab.com/ubiqsecurity/ubiq-php.git
$ cd ubiq-php
$ composer install
```

## View Program Options

From the top level of the source directory:

```sh
$ php -f examples/ubiq_sample.php -- -h
```
<pre>
Usage: examples/ubiq_sample.php -e|-d -i INFILE -o OUTFILE
Encrypt or decrypt files using the Ubiq service

  -h                       Show this help message and exit
  -V                       Show program's version number and exit
  -e                       Encrypt the contents of the input file and write
                             the results to the output file
  -d                       Decrypt the contents of the input file and write
                             the results to the output file
  -i INFILE                Set input file name
  -o OUTFILE               Set output file name
  -c CREDENTIALS           Set the file name with the API credentials
                             (default: ~/.ubiq/credentials)
  -P PROFILE               Identify the profile within the credentials file
</pre>

#### Demonstrate using the simple API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
$ php -f examples/ubiq_sample.php -- -i README.md -o /tmp/readme.enc -e -c ./credentials
```

#### Demonstrate using the simple API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
$ php -f examples/ubiq_sample.php -- -i /tmp/readme.enc -o /tmp/README.out -d -c ./credentials
```
