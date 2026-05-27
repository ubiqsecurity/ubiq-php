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

    // Vendor autoload first so phpseclib (BigInteger) is available
    // for the typed-bridge base-N helpers in src/Encryption.php.
    $_autoload = realpath(dirname(__FILE__) . '/../vendor/autoload.php');
    if ($_autoload) {
        require_once $_autoload;
    }
    require_once realpath(dirname(__FILE__) . '/../src/Ubiq.php');

    /*

    Usage: php ubiq_load_test.php -i INPUT [-c CREDENTIALS] [-p PROFILE] [-N MAX_ROWS]
    Encrypt or decrypt data using the Ubiq structured encryption service.

    Dispatches per row by the dataset's data_type returned from the
    server (mirrors the Java / .NET load harnesses):
      - integer    → \Ubiq\encryptInteger / \Ubiq\decryptInteger
      - date       → \Ubiq\encryptDate / \Ubiq\decryptDate
      - datetime   → \Ubiq\encryptDateTime / \Ubiq\decryptDateTime
      - string / token / default → \Ubiq\encrypt / \Ubiq\decrypt

    Calls \Ubiq\loadCache() once up front so every dataset's config
    and keys are populated in a single network round-trip (Go pattern).

    -x
    Print information regarding the failing records.

    -e
    Maximum allowed average encrypt time in microseconds.
    Not including first call to server.

    -d
    Maximum allowed average decrypt time in microseconds.
    Not including first call to server.

    -E
    Maximum allowed total encrypt time in microseconds.
    Not including first call to server.

    -D
    Maximum allowed total decrypt time in microseconds.
    Not including first call to server.

    -i <INFILE>
    Set input file name. Accepts a file, a directory (every JSON
    inside is walked), or a glob-prefix. Falls back to the
    UBIQ_TEST_DATA_FILE environment variable when -i is omitted.

    -N <MAX_ROWS>
    Process at most this many rows per input file. Useful for
    tiered runs (10k → 100k → full). 0 / unset = no cap.

    -c <CREDENTIALS>
    Set the file name with the API credentials (default: ~/.ubiq/credentials).
    Falls back to the UBIQ_TEST_CREDENTIALS environment variable.

    -p <PROFILE>
    Identify the profile within the credentials file (default: default).
    */
    $commands = getopt("hxe:E:d:D:c:p:s:i:N:");
    
    if (array_key_exists('h', $commands)) {
        showHelp();
        exit;
    }

    doTests($commands);

    function doTests($commands)
    {
        debug('Begin doTests');

        $credentials_file = $commands['c'] ?? getenv('UBIQ_TEST_CREDENTIALS') ?: NULL;
        $profile_name = $commands['p'] ?? NULL;
        $file = $commands['i'] ?? getenv('UBIQ_TEST_DATA_FILE') ?: NULL;
        $print_failures = array_key_exists('x', $commands);
        $max_average_encrypt = $commands['e'] ?? 0;
        $max_total_encrypt = $commands['E'] ?? 0;
        $max_average_decrypt = $commands['d'] ?? 0;
        $max_total_decrypt = $commands['D'] ?? 0;
        $max_rows_per_file = (int) ($commands['N'] ?? 0);

        $files = [];
        $times = []; // [dataset][encrypt|decrypt|count]
        $totals = ['encrypt' => 0, 'decrypt' => 0, 'count' => 0];
        $errors = [];

        if (empty($file)) {
            die('Must specify infile (via -i or UBIQ_TEST_DATA_FILE env var)');
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
            }
        } elseif (is_dir(dirname($file))) {
            foreach (scandir(dirname($file)) as $_file) {
                if ($_file !== '.' && $_file !== '..') {
                    if (strpos($_file, str_replace('*', '', basename($file))) === 0) {
                        $files[] = realpath(dirname($file) . DIRECTORY_SEPARATOR . $_file);
                    }
                }
            }
        } else {
            die('Infile ' . $file . ' does not exist');
        }

        debug('Files found ' . sizeof($files));

        $credentials = new Ubiq\Credentials();
        if (!empty($credentials_file)) {
            $credentials->load($credentials_file, $profile_name ?? 'default');
        }

        // Single-call cache pre-hydrate so every dataset's config +
        // keys are loaded before the per-row loop, instead of N
        // per-dataset HTTP fetches. Mirrors ubiq-go's LoadCache flow.
        debug('Pre-hydrating dataset cache via \\Ubiq\\loadCache()');
        \Ubiq\loadCache($credentials);

        foreach ($files as $file) {
            $json = json_decode(file_get_contents($file), TRUE);
            $row_count = sizeof($json);
            $cap = ($max_rows_per_file > 0 && $max_rows_per_file < $row_count)
                ? $max_rows_per_file : $row_count;

            debug('Records found in ' . $file . ' ' . $row_count
                . ($cap < $row_count ? ' (capped to ' . $cap . ' via -N)' : ''));

            foreach ($json as $idx => $row) {
                if ($idx >= $cap) {
                    break;
                }
                if ($idx % 1000 == 0 || ($row_count <= 1001)) {
                    debug('Processing record ' . $idx . ' of ' . $cap . ' in ' . $file);
                    if ($row_count < 1001) {
                        debug('Dataset: ' . $row['dataset'] . ' plaintext ' . $row['plaintext'] . ' ciphertext ' . $row['ciphertext']);
                    }
                }

                // Warm-up: first call per dataset is excluded from
                // timings so the dataset/key fetch (or cache miss
                // path) doesn't bias the averages.
                if (!array_key_exists($row['dataset'], $times)) {
                    dispatchEncrypt($credentials, $row['dataset'], $row['plaintext']);
                    dispatchDecrypt($credentials, $row['dataset'], $row['ciphertext']);

                    $times[$row['dataset']] = [
                      'encrypt' => 0,
                      'decrypt' => 0,
                      'count' => 0
                    ];
                }

                $etime = hrtime(true);
                $actual_cipher = dispatchEncrypt($credentials, $row['dataset'], $row['plaintext']);

                $dtime = hrtime(true);
                $actual_plain = dispatchDecrypt($credentials, $row['dataset'], $row['ciphertext']);

                $ftime = hrtime(true);

                $cipher_match = compareTyped($credentials, $row['dataset'], $actual_cipher, $row['ciphertext']);
                $plain_match = compareTyped($credentials, $row['dataset'], $actual_plain, $row['plaintext']);

                if (!$cipher_match || !$plain_match) {
                    $errors[] = [
                        'idx' => $idx,
                        'dataset' => $row['dataset'],
                        'expected_ciphertext' => $row['ciphertext'],
                        'expected_plaintext' => $row['plaintext'],
                        'actual_ciphertext' => formatTyped($actual_cipher),
                        'actual_plaintext' => formatTyped($actual_plain)
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
        }

        if ($totals['count'] > 0) {
            debug('Encrypt records count ' . $totals['count'] . '. Times in microseconds');
            foreach ($times as $dataset => $row) {
                if ($row['count'] == 0) continue;
                debug("\tDataset: " . $dataset . ", record_count: " . $row['count'] . ", Average: " . round($row['encrypt'] / $row['count']) . ", total " . $row['encrypt']);
            }
            debug("\tTotal: record_count: " . $totals['count'] . ", Average: " . round($totals['encrypt'] / $totals['count']) . ", total " . $row['encrypt']);

            debug('Decrypt records count ' . $totals['count'] . '. Times in microseconds');
            foreach ($times as $dataset => $row) {
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


    function showHelp()
    {
        echo "
            Usage: php ubiq_load_test.php -e|-d INPUT -s|-p -n FFS [-c CREDENTIALS] [-P PROFILE]
            Encrypt or decrypt data using the Ubiq structured encryption service
            
            -x
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

    /**
     * Server-driven encrypt dispatch. Reads the dataset's data_type
     * from the (cached) Dataset object and routes to the matching
     * typed entry point. Returns the native type — int for integer
     * datasets, \DateTimeImmutable for date/datetime, string for
     * string/token/default.
     */
    function dispatchEncrypt(\Ubiq\Credentials $creds, string $datasetName, string $plainValue)
    {
        $dataset = $creds::$datasetmanager->getDataset($creds, $datasetName);
        switch ($dataset->getDataType()) {
            case 'integer':
                return \Ubiq\encryptInteger($creds, (int) $plainValue, $datasetName);
            case 'date':
                return \Ubiq\encryptDate($creds, new \DateTimeImmutable($plainValue), $datasetName);
            case 'datetime':
                return \Ubiq\encryptDateTime($creds, new \DateTimeImmutable($plainValue), $datasetName);
            default:
                return \Ubiq\encrypt($creds, $plainValue, $datasetName);
        }
    }

    /**
     * Server-driven decrypt dispatch. Parses the fixture's string
     * ciphertext into the right native type for the dataset, then
     * routes to the matching typed entry point. Returns the native
     * type (same shape as dispatchEncrypt).
     */
    function dispatchDecrypt(\Ubiq\Credentials $creds, string $datasetName, string $cipherValue)
    {
        $dataset = $creds::$datasetmanager->getDataset($creds, $datasetName);
        switch ($dataset->getDataType()) {
            case 'integer':
                return \Ubiq\decryptInteger($creds, (int) $cipherValue, $datasetName);
            case 'date':
                return \Ubiq\decryptDate($creds, new \DateTimeImmutable($cipherValue), $datasetName);
            case 'datetime':
                return \Ubiq\decryptDateTime($creds, new \DateTimeImmutable($cipherValue), $datasetName);
            default:
                return \Ubiq\decrypt($creds, $cipherValue, $datasetName);
        }
    }

    /**
     * Type-aware equality between an actual dispatch result and the
     * expected value (which is always a string in the JSON fixture).
     */
    function compareTyped(\Ubiq\Credentials $creds, string $datasetName, $actual, string $expectedStr): bool
    {
        $dataset = $creds::$datasetmanager->getDataset($creds, $datasetName);
        switch ($dataset->getDataType()) {
            case 'integer':
                return is_int($actual) && $actual === (int) $expectedStr;
            case 'date':
            case 'datetime':
                if (!($actual instanceof \DateTimeImmutable)) {
                    return false;
                }
                $expected = new \DateTimeImmutable($expectedStr);
                return $actual->getTimestamp() === $expected->getTimestamp();
            default:
                return is_string($actual) && $actual === $expectedStr;
        }
    }

    /**
     * Stringify a typed value for error reporting.
     */
    function formatTyped($value): string
    {
        if ($value instanceof \DateTimeImmutable) {
            return $value->format(\DateTimeInterface::ATOM);
        }
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }
        return (string) $value;
    }
