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

require_once implode(
    DIRECTORY_SEPARATOR,
    array(__DIR__, '..', 'src/Ubiq.php')
);

const UBIQ_SAMPLE_MAX_SIMPLE_SIZE = 50 * 1024 * 1024;

error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE | E_STRICT);

// @codingStandardsIgnoreLine
abstract class UbiqSampleMode
{
    const UNSPEC = 0;
    const ENCRYPT = 1;
    const DECRYPT = 2;
}

/**
 * Encrypt a file using the simple encryption API
 *
 * @param $creds The credentials to use for the operation
 * @param $ifp   The resource associated with the input file
 * @param $ofp   The resource associated with the output file
 * @param $size  The number of bytes in the input file
 *
 * @return None
 */
function ubiqSampleSimpleEncrypt(
    Ubiq\Credentials $creds, &$ifp, &$ofp, int $size
) : void {
    $pt = fread($ifp, $size);
    $ct = Ubiq\encrypt($creds, $pt);
    fwrite($ofp, $ct);
}

/**
 * Decrypt a file using the simple decryption API
 *
 * @param $creds The credentials to use for the operation
 * @param $ifp   The resource associated with the input file
 * @param $ofp   The resource associated with the output file
 * @param $size  The number of bytes in the input file
 *
 * @return None
 */
function ubiqSampleSimpleDecrypt(
    Ubiq\Credentials $creds, &$ifp, &$ofp, int $size
) : void {
    $ct = fread($ifp, $size);
    $pt = Ubiq\decrypt($creds, $ct);
    fwrite($ofp, $pt);
}

/**
 * Display sample usage to standard error
 *
 * @param $cmd The name of the command
 * @param $err The error to display, if any
 *
 * @return None
 */
function ubiqSampleUsage(string $cmd, ?string $err) : void
{
    if ($err) {
        fwrite(STDERR, "$err\n\n");
    }

    fwrite(STDERR, "Usage: $cmd -e|-d -i INFILE -o OUTFILE\n");
    fwrite(STDERR, "Encrypt or decrypt files using the Ubiq service\n");
    fwrite(STDERR, "\n");
    fwrite(STDERR, "  -h                       ");
    fwrite(STDERR, "Show this help message and exit\n");
    fwrite(STDERR, "  -V                       ");
    fwrite(STDERR, "Show program's version number and exit\n");
    fwrite(STDERR, "  -e                       ");
    fwrite(STDERR, "Encrypt the contents of the input file and write\n");
    fwrite(STDERR, "                           ");
    fwrite(STDERR, "  the results to the output file\n");
    fwrite(STDERR, "  -d                       ");
    fwrite(STDERR, "Decrypt the contents of the input file and write\n");
    fwrite(STDERR, "                           ");
    fwrite(STDERR, "  the results to the output file\n");
    fwrite(STDERR, "  -i INFILE                Set input file name\n");
    fwrite(STDERR, "  -o OUTFILE               Set output file name\n");
    fwrite(STDERR, "  -c CREDENTIALS           ");
    fwrite(STDERR, "Set the file name with the API credentials\n");
    fwrite(STDERR, "                           ");
    fwrite(STDERR, "  (default: ~/.ubiq/credentials)\n");
    fwrite(STDERR, "  -P PROFILE               ");
    fwrite(STDERR, "Identify the profile within the credentials file\n");
}

/**
 * Parse command line for sample application
 *
 * PHP's getopt() is hopelessly broken in that it simply ignores
 * unrecognized command line options. This code simply parses the
 * options provided by getopt() without trying to jump through any
 * extra hoops to catch those bad options.
 *
 * The function guarantees that necessary options will be in the
 * returned array. Optional arguments are either present or not.
 * If required arguments are missing, the function causes the program
 * to exit unsuccessfully. The -h and -V options are also handled
 * by this function and cause the program to exit successfully
 *
 * @param $argv The argument vector given to the program
 *
 * @return An associative array containing 'mode', 'infile', 'outfile,
 *         and optionally 'credfile' and 'profile'
 */
function ubiqSampleGetopt(array $argv) : array
{
    $opts = array();

    $args = getopt('hVedi:o:c:P:', array(), $index);
    if (count($argv) > 1 && $index != count($argv)) {
        ubiqSampleUsage($argv[0], "unrecognized argument: $argv[$index]");
        exit(1);
    }

    if (array_key_exists('h', $args)) {
        ubiqSampleUsage($argv[0], null);
        exit(0);
    }

    if (array_key_exists('V', $args)) {
        fwrite(STDERR, "version 0.0.0\n");
        exit(0);
    }

    /* -e and -d both specified */
    if ((array_key_exists('e', $args) && array_key_exists('d', $args))
        /* -e specified more than once */
        || (array_key_exists('e', $args) && is_array($args['e']))
        /* -d specified more than once */
        || (array_key_exists('d', $args) && is_array($args['d']))
    ) {
        ubiqSampleUsage(
            $argv[0], 'please specify one of encrypt or decrypt once'
        );
        exit(1);
    } else if (array_key_exists('e', $args)) {
        $opts['mode'] = UbiqSampleMode::ENCRYPT;
    } else if (array_key_exists('d', $args)) {
        $opts['mode'] = UbiqSampleMode::DECRYPT;
    } else {
        ubiqSampleUsage($argv[0], 'encrypt / decrypt operation not specified');
        exit(1);
    }

    /*
     * input file handling
     */
    if (array_key_exists('i', $args) && is_array($args['i'])) {
        ubiqSampleUsage($argv[0], 'please specify only one input file');
        exit(1);
    } else if (array_key_exists('i', $args)) {
        $opts['infile'] = $args['i'];
    } else {
        ubiqSampleUsage($argv[0], 'input file not specified');
        exit(1);
    }

    /*
     * output file handling
     */
    if (array_key_exists('o', $args) && is_array($args['o'])) {
        ubiqSampleUsage($argv[0], 'please specify only one output file');
        exit(1);
    } else if (array_key_exists('o', $args)) {
        $opts['outfile'] = $args['o'];
    } else {
        ubiqSampleUsage($argv[0], 'output file not specified');
        exit(1);
    }

    /*
     * credentials file handling
     */
    if (array_key_exists('c', $args) && is_array($args['c'])) {
        ubiqSampleUsage($argv[0], 'please specify only one credentials file');
        exit(1);
    } else if (array_key_exists('c', $args)) {
        $opts['credfile'] = $args['c'];
    }

    /*
     * profile handling
     */
    if (array_key_exists('P', $args) && is_array($args['P'])) {
        ubiqSampleUsage($argv[0], 'please specify only one profile name');
        exit(1);
    } else if (array_key_exists('P', $args)) {
        $opts['profile'] = $args['P'];
    }

    return $opts;
}

/**
 * Main program function (a la C or C++)
 *
 * @param $argv The command line argument vector
 *
 * @return An integer signifying the exit status of the program
 */
function main(array $argv) : int
{
    $opts = ubiqSampleGetopt($argv);

    $creds = new Ubiq\Credentials;
    $credfile = array_key_exists('credfile', $opts) ?
              $opts['credfile'] : null;
    $profile = array_key_exists('profile', $opts) ?
              $opts['profile'] : null;
    if ($credfile || $profile) {
        if (!$creds->load($credfile, $profile)) {
            fwrite(STDERR, "unable to load credentials\n");
            exit(1);
        }
    }

    $ifp = @fopen($opts['infile'], 'rb');
    if (!$ifp) {
        fwrite(STDERR, 'unable to open input file: ' . $opts['infile'] . "\n");
        exit(1);
    }

    fseek($ifp, 0, SEEK_END);
    $size = ftell($ifp);
    fseek($ifp, 0, SEEK_SET);

    if ($size > UBIQ_SAMPLE_MAX_SIMPLE_SIZE) {
        fwrite(
            STDERR,
            "NOTE: This is only for demonstration purposes and" .
            " is designed to work on memory\n"
        );
        fwrite(
            STDERR,
            "      constrained devices.  Therefore, this sample" .
            " application does not support\n"
        );
        fwrite(
            STDERR,
            "      files larger than " . UBIQ_SAMPLE_MAX_SIMPLE_SIZE .
            " bytes in order to avoid excessive resource\n"
        );
        fwrite(
            STDERR,
            "      usage on resource constrained IoT devices\n"
        );
        fclose($ifp);
        exit(1);
    }

    $ofp = @fopen($opts['outfile'], 'wb+');
    if (!$ofp) {
        fwrite(
            STDERR, 'unable to open output file: ' . $opts['outfile'] . "\n"
        );
        fclose($ifp);
        exit(1);
    }

    if ($opts['mode'] == UbiqSampleMode::ENCRYPT) {
        ubiqSampleSimpleEncrypt($creds, $ifp, $ofp, $size);
    } else /* decrypt */ {
        ubiqSampleSimpleDecrypt($creds, $ifp, $ofp, $size);
    }

    fclose($ofp);
    fclose($ifp);

    return 0;
}

return main($argv);
