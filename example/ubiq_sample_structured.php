<?php

    // Subject to the foregoing terms and conditions, Ubiq hereby grants to You, at
    // no cost, a perpetual, worldwide, non-exclusive, royalty-free, irrevocable
    // (except as stated herein) license to the Software, including all right to
    // reproduce, prepare derivative works of, sublicense, and distribute the same.
    // In the event You institute any litigation, or otherwise make any claim,
    // against Ubiq for any reason (including a cross-claim or counterclaim in
    // a lawsuit), or violate the terms of this license in any way, this license
    // shall terminate automatically, without notice or liability, as of the date
    // such litigation is filed or such violation occurs.  This license does not
    // grant permission to use Ubiq’s trade names, trademarks, service marks, or
    // product names in any way without Ubiq’s express prior written consent.
    // THE SOFTWARE IS PROVIDED ON AN “AS IS” BASIS, WITHOUT WARRANTIES OR
    // CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, WITHOUT
    // LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
    // MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE. YOU ASSUME ANY
    // AND ALL RISKS ASSOCIATED WITH YOUR EXERCISE OF ANY RIGHTS GRANTED HEREUNDER.
    // UBIQ SHALL HAVE LIABILITY TO YOU OR TO ANY THIRD PARTIES WITH RESPECT TO
    // THIS LICENSE FOR (i) SPECIAL, CONSEQUENTIAL, EXEMPLARY, INCIDENTAL, OR
    // PUNITIVE DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOST PROFITS, LOST
    // REVENUES, LOST BUSINESS OPPORTUNITIES, LOSS OF USE OR EQUIPMENT DOWNTIME,
    // AND LOSS OF OR CORRUPTION TO DATA), REGARDLESS OF THE LEGAL THEORY UNDER
    // WHICH THEY ARE SOUGHT (INCLUDING, BUT NOT LIMITED TO ACTIONS FOR BREACH OF
    // CONTRACT, NEGLIGENCE, STRICT LIABILITY, RESCISSION AND BREACH OF WARRANTY),
    // EVEN IF UBIQ HAD BEEN ADVISED OF, OR SHOULD HAVE FORESEEN, THE POSSIBILITY
    // OF SUCH DAMAGES, OR (ii) DIRECT DAMAGES EXCEEDING ONE DOLLAR.  IN NO EVENT
    // SHALL UBIQ BE LIABLE FOR COSTS OF PROCUREMENT OF SUBSTITUTE PRODUCTS.
    // YOU ACKNOWLEDGE AND AGREE THAT ALL LIMITATIONS AND DISCLAIMERS APPLICABLE
    // TO THIS LICENSE ARE ESSENTIAL ELEMENTS OF THIS LICENSE AND THAT THESE
    // REFLECT AN EQUITABLE ALLOCATION OF RISK BETWEEN THE PARTIES AND THAT IN
    // THEIR ABSENCE THE TERMS OF THIS LICENSE WOULD BE SUBSTANTIALLY DIFFERENT.


    error_reporting(-1);
    ini_set('display_errors', 1);
    ini_set('memory_limit', '1G');

    require_once realpath(dirname(__FILE__) . '/../src/Ubiq.php');

    /*

    Usage: php ./example/ubiq_sample_structured.php -e|-d INPUT -s|-p -n Dataset [-c CREDENTIALS] [-P PROFILE]
    Encrypt or decrypt data using the Ubiq structured datasets
    -h                       Show this help message and exit
    -V                       Show program's version number and exit
    -e INPUT                 Encrypt the supplied input string
                                escape or use quotes if input string
                                contains special characters
    -d INPUT                 Decrypt the supplied input string
                                escape or use quotes if input string
                                contains special characters
    -n Dataset               Use the supplied Field Format Specification
    -c CREDENTIALS           Set the file name with the API credentials
                                (default: ~/.ubiq/credentials)
    -P PROFILE               Identify the profile within the credentials file
    */
    $commands = getopt("he:d:n:c:p:s:i:");
    
    if ($commands['h'] ?? FALSE) {
        showHelp();
        exit;
    }

    $dataset = $commands['n'] ?? NULL;
    $credentials_file = $commands['c'] ?? NULL;
    $profile_name = $commands['p'] ?? NULL;
    $iterations = $commands['i'] ?? NULL;

    if (empty($dataset)) {
        die('Must specify dataset');
    }

    $credentials = new Ubiq\Credentials();
    if (!empty($credentials_file)) {
        $credentials->load($credentials_file, $profile_name ?? 'default');
    }

    if (!empty($commands['d'])) {
        doDecrypt($credentials, $commands['d'], $dataset, $iterations);
    }
    elseif (!empty($commands['e'])) {
        doEncrypt($credentials, $commands['e'], $dataset, $iterations);
    }
    elseif (!empty($commands['s'])) {
        doEncryptForSearch($credentials, $commands['s'], $dataset);
    }

    function showHelp()
    {
        echo "
            Usage: ubiq_sample_structured.js -e|-d INPUT -s|-b -n Dataset [-c CREDENTIALS] [-P PROFILE]
            Encrypt or decrypt data using the Ubiq structured encryption service
            
            -e <input>
            Encrypt the supplied input string escape or use quotes if input string
      
            -d <input>
            Decrypt the supplied input string escape or use quotes if input string

            -es <input>
            Encrypt the supplied input string for search escape or use quotes if input string

            -n <Dataset>
            Use the supplied dataset name
            
            -i <iterations>
            Iterate the action this number of times
            
            -c <CREDENTIALS>
            Set the file name with the API credentials (default: ~/.ubiq/credentials)
            
            -p <PROFILE>
            Identify the profile within the credentials file (default: default)
        ";
    }

    function doDecrypt($credentials, $string, $dataset, $iterations = 1) {
        debug('Begin doDecrypt');
        for ($i = 0; $i < $iterations; $i++) {
            $value = \Ubiq\decrypt($credentials, $string, $dataset);
            
            if ($i % 100 == 0 || $iterations < 20) {
                debug('Finished doDecrypt iteration ' . ($i+1) . ' of ' . $iterations);
            }
        }
        debug('Finished doDecrypt');
        debug('Decrypted ' . $string . ' to ' . $value);
    }

    function doEncrypt($credentials, $string, $dataset, $iterations = 1) {
        debug('Begin doEncrypt');
        for ($i = 0; $i < $iterations; $i++) {
            $value = \Ubiq\encrypt($credentials, $string, $dataset);
    
            if ($i % 100 == 0 || $iterations < 20) {
                debug('Finished doEncrypt iteration ' . ($i+1) . ' of ' . $iterations);
            }
        }
        debug('Finished doEncrypt');
        debug('Encrypted ' . $string . ' to ' . $value);
    }

    function doEncryptForSearch($credentials, $string, $dataset) {
        debug('Begin doEncryptForSearch');
        $values = \Ubiq\encryptForSearch($credentials, $string, $dataset);
        debug('Finished encrydoEncryptForSearchption');
        debug('Encrypted ' . $string . ' to ');
        print_R($values);
    }

    function debug($msg) {
        echo (new DateTime())->format('Y-m-d H:i:s.v') . ' ' . $msg . PHP_EOL;
    }
