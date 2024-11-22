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

    Usage: php ubiq_load_test.php -e|-d INPUT -s|-p -n FFS [-c CREDENTIALS] [-P PROFILE]
    Encrypt or decrypt data using the Ubiq structured encryption service
    
    -p
    Print information regarding the failing records.
    
    -e
    Maximum allowed average encrypt time in microseconds.
    Not including first call to server
    
    -d
    Maximum allowed average decrypt time in microseconds.
    Not including first call to server
    
    -E
    Maximum allowed total encrypt time in microseconds.
    Not including first call to server
    
    -D
    Maximum allowed total decrypt time in microseconds.
    Not including first call to server

    -i <INFILE>
    Set input file name
    
    -c <CREDENTIALS>
    Set the file name with the API credentials (default: ~/.ubiq/credentials)
    
    -p <PROFILE>
    Identify the profile within the credentials file (default: default)
    */
    $commands = getopt("heEdDc:p:s:i:");
    
    if ($commands['h'] ?? FALSE) {
        showHelp();
        exit;
    }

    doTests($commands);

    function doTests($commands)
    {
        debug('Begin doTests');

        $credentials_file = $commands['c'] ?? NULL;
        $profile_name = $commands['p'] ?? NULL;
        $file = $commands['i'] ?? NULL;
        $print_failures = $commands['p'] ?? FALSE;
        $max_average_encrypt = $commands['e'] ?? 0;
        $max_total_encrypt = $commands['E'] ?? 0;
        $max_average_decrypt = $commands['d'] ?? 0;
        $max_total_decrypt = $commands['D'] ?? 0;
        
        $files = [];
        $times = []; // [dataset][encrypt|decrypt|count]
        $totals = ['encrypt' => 0, 'decrypt' => 0, 'count' => 0];
        $errors = [];
        
        if (empty($file)) {
            die('Must specify infile');
        }
    
        if (file_exists($file)) {
            if (is_file($file)) {
                $files[] = $file;
            } elseif (is_dir($file)) {
                foreach (scandir($file) as $_file) {
                    if ($_file !== '.' && $_file !== '..') {
                        $files[] = realpath($file . DIRECTORY_SEPARATOR . $_file);
                    }
                }
            } else {
                die('Infile ' . $file . ' is not a valid file or directory');
            }
        } else {
            die('Infile ' . $file . ' does not exist');
        }

        debug('Files found ' . sizeof($files));

        $credentials = new Ubiq\Credentials();
        if (!empty($credentials_file)) {
            $credentials->load($credentials_file, $profile_name ?? 'default');
        }

        foreach ($files as $file) {
            $json = json_decode(file_get_contents($file), TRUE);

            debug('Records found in ' . $file . ' ' . sizeof($json));

            foreach ($json as $idx => $row) {

                if ($row['dataset'] == 'UTF8_STRING_COMPLEX') continue;
                // if ($idx > 25) continue;

                if ($idx % 1000 == 0 || sizeof($json) <= (1000 && $idx % 50 == 0)) {
                    debug('Processing record ' . $idx . ' of ' . sizeof($json) . ' in ' . $file);
                    if (sizeof($json) < 25) {
                        debug('Dataset: ' . $row['dataset'] . ' plaintext ' . $row['plaintext'] . ' ciphertext ' . $row['ciphertext']);
                    }
                }

                if (!array_key_exists($row['dataset'], $times)) {
                    $ciphertext = \Ubiq\encrypt($credentials, $row['plaintext'], $row['dataset']);
                    $plaintext = \Ubiq\decrypt($credentials, $row['ciphertext'], $row['dataset']);

                    $times[$row['dataset']] = [
                      'encrypt' => 0,
                      'decrypt' => 0,
                      'count' => 0
                    ];
                }

                $etime = hrtime(true);
                $ciphertext = \Ubiq\encrypt($credentials, $row['plaintext'], $row['dataset']);

                $dtime = hrtime(true);
                $plaintext = \Ubiq\decrypt($credentials, $row['ciphertext'], $row['dataset']);

                $ftime = hrtime(true);

                if ($ciphertext != $row['ciphertext'] || $plaintext != $row['plaintext']) {
                    $errors[] = [
                        'idx' => $idx,
                        'dataset' => $row['dataset'],
                        'expected_ciphertext' => $row['ciphertext'],
                        'expected_plaintext' => $row['plaintext'],
                        'actual_ciphertext' => $ciphertext,
                        'actual_plaintext' => $plaintext
                    ];
                }
                else {
                    $times[$row['dataset']]['encrypt'] += ($ftime-$etime)/1000;
                    $times[$row['dataset']]['decrypt'] += ($ftime-$dtime)/1000;
                    $times[$row['dataset']]['count'] ++;

                    $totals['encrypt'] += ($ftime-$etime)/1000;
                    $totals['decrypt'] += ($ftime-$dtime)/1000;
                    $totals['count'] ++;
                }
            }

            
            debug('Encrypt records count ' . $totals['count'] . '. Times in microseconds');
            foreach ($times as $dataset => $row) {
                if ($row['count'] == 0) continue;
                debug("\tDataset: " . $dataset . ", record_count: " . $row['count'] . ", Average: " . round($row['encrypt'] / $row['count']) . ", total " . $row['encrypt']);
            }
            debug("\tTotal: record_count: " . $totals['count'] . ", Average: " . round($totals['encrypt'] / $totals['count']) . ", total " . $row['encrypt']);

            debug('Decrypt records count ' . $totals['count'] . '. Times in microseconds');
            foreach ($times as $row) {
                if ($row['count'] == 0) continue;
                debug("\tDataset: " . $dataset . ", record_count: " . $row['count'] . ", Average: " . round($row['decrypt'] / $row['count']) . ", total " . $row['encrypt']);
            }
            debug("\tTotal: record_count: " . $totals['count'] . ", Average: " . round($totals['decrypt'] / $totals['count']) . ", total " . $row['encrypt']);

            if ($max_average_encrypt > 0 && $totals['encrypt'] / $totals['count'] > $max_average_encrypt) {
                debug('FAILED: Exceeded maximum allowed average encrypt threshold of ' . $max_average_encrypt . ' microseconds');
            }
            elseif ($max_average_encrypt > 0) {
                debug('PASSED: Maximum allowed average encrypt threshold of ' . $max_average_encrypt . ' microseconds');
            }

            if ($max_average_encrypt > 0 && $totals['decrypt'] / $totals['count']) {
                debug('FAILED: Exceeded maximum allowed average decrypt threshold of ' . $max_average_decrypt . ' microseconds');
            }
            elseif ($max_average_decrypt > 0) {
                debug('PASSED: Maximum allowed average decrypt threshold of ' . $max_average_decrypt . ' microseconds');
            }

            if ($max_total_encrypt > 0 && $totals['encrypt']) {
                debug('FAILED: Exceeded maximum allowed encrypt threshold of ' . $max_total_encrypt . ' microseconds');
            }
            elseif ($max_total_encrypt > 0) {
                debug('PASSED: Maximum allowed encrypt threshold of ' . $max_total_encrypt . ' microseconds');
            }

            if ($max_total_decrypt > 0 && $totals['decrypt']) {
                debug('FAILED: Exceeded maximum allowed decrypt threshold of ' . $max_total_decrypt . ' microseconds');
            }
            elseif ($max_total_encrypt > 0) {
                debug('PASSED: Maximum allowed decrypt threshold of ' . $max_total_decrypt . ' microseconds');
            }

            if (empty($errors)) {
                debug('PASSED: ' . $totals['count'] . ' records validated');
            }
            else {
                debug('FAILED: ' . sizeof($errors) . ' records failed');
                
                if ($print_failures) {
                    foreach ($errors as $row) {
                        $string = "\tIdx: " . $row['idx'] . " Dataset: " . $row['dataset'];
                        if ($row['expected_ciphertext'] != $row['actual_ciphertext']) {
                            $string .= " encrypt of " . $row['expected_plaintext'] . " should be " . $row['expected_ciphertext'] . " vs " . $row['actual_ciphertext'];
                        }
                        if ($row['expected_plaintext'] != $row['actual_plaintext']) {
                            $string .= " decrypt of " . $row['expected_ciphertext'] . " should be " . $row['expected_plaintext'] . " vs " . $row['actual_plaintext'];
                        }
                        debug($string);
                    }
                }
            }
            
            debug('Finished doTests');
        }
    }


    function showHelp()
    {
        echo "
            Usage: php ubiq_load_test.php -e|-d INPUT -s|-p -n FFS [-c CREDENTIALS] [-P PROFILE]
            Encrypt or decrypt data using the Ubiq structured encryption service
            
            -p
            Print information regarding the failing records.
            
            -e
            Maximum allowed average encrypt time in microseconds.
            Not including first call to server
            
            -d
            Maximum allowed average decrypt time in microseconds.
            Not including first call to server
            
            -E
            Maximum allowed total encrypt time in microseconds.
            Not including first call to server
            
            -D
            Maximum allowed total decrypt time in microseconds.
            Not including first call to server

            -i <INFILE>
            Set input file name
            
            -c <CREDENTIALS>
            Set the file name with the API credentials (default: ~/.ubiq/credentials)
            
            -p <PROFILE>
            Identify the profile within the credentials file (default: default)
        ";
    }

    function debug($msg) {
        echo (new DateTime())->format('Y-m-d H:i:s.v') . ' ' . $msg . PHP_EOL;
    }
