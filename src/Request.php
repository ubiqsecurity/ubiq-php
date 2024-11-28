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

namespace Ubiq;

/**
 * HTTP/S request object implementing Ubiq signature scheme
 *
 * @category Cryptography
 * @package  Ubiq-PHP
 * @author   Ubiq Security <support@ubiqsecurity.com>
 * @license  https://opensource.org/licenses/MIT MIT
 * @link     https://gitlab.com/ubiqsecurity/ubiq-php
 */
class Request
{
    private $_papi;
    private $_sapi;
    private $_curl;

    /**
     * Sign an http/s request
     *
     * @param string $method  One of 'GET', 'POST', etc.
     * @param string $url     The URL to which to make the request
     * @param string $content Content to be sent to the server or null
     * @param string $ctype   The content type
     *
     * @return Associative array of headers to add to the HTTP request
     */
    private function _sign(
        string $method, string $url,
        ?string $content, ?string $ctype
    ) {
        $headers = array();
        $urlparts = parse_url($url);

        $target = &$headers['(request-target)'];
        $target = strtolower($method) . ' ';
        if (array_key_exists('path', $urlparts)) {
            $target .= $urlparts['path'];
        } else {
            $target .= '/';
        }
        if (array_key_exists('query', $urlparts)) {
            $target .= '?' . $urlparts['query'];
        }

        $tz = new \DateTimeZone(date_default_timezone_get());
        $offset = $tz->getOffset(new \DateTime('now', $tz));

        $created = time();
        $headers['(created)'] = strval($created);
        $headers['Date'] = date('D, d M Y H:i:s', $created-$offset) . ' GMT';

        $headers['Host'] = $urlparts['host'];
        if (($urlparts['scheme'] == 'http'
            && array_key_exists('port', $urlparts)
            && $urlparts['port'] != 80)  
            || ($urlparts['scheme'] == 'https'
            && array_key_exists('port', $urlparts)
            && $urlparts['port'] != 443)
        ) {
            $headers['Host'] .= ':' . strval($urlparts['port']);
        }

        $headers['Digest']  = 'SHA-512=';
        $headers['Digest'] .= base64_encode(
            hash('sha512', $content ? $content : '', true)
        );

        if ($content) {
            $headers['Content-Length'] = strval(strlen($content));
            $headers['Content-Type'] = $ctype;
        }

        $hdrs = array();
        $hmac = hash_init('sha512', HASH_HMAC, $this->_sapi);
        foreach (array('(created)',
                       '(request-target)',
                       'Content-Length',
                       'Content-Type',
                       'Date',
                       'Digest',
                       'Host') as $k) {
            if (array_key_exists($k, $headers)) {
                $lk = strtolower($k);
                array_push($hdrs, $lk);
                hash_update($hmac, $lk . ': ' . $headers[$k] . "\n");
            }
        }
        $signature = base64_encode(hash_final($hmac, true));

        unset($headers['(created)']);
        unset($headers['(request-target)']);

        $sighdr  = &$headers['Signature'];
        $sighdr  = 'keyId="' . $this->_papi . '"';
        $sighdr .= ', algorithm="hmac-sha512"';
        $sighdr .= ', created=' . strval($created);
        $sighdr .= ', headers="' . implode(' ', $hdrs) . '"';
        $sighdr .= ', signature="' . $signature . '"';

        return $headers;
    }

    /**
     * Do an http/s request async
     *
     * @param string $method  One of 'GET', 'POST', etc.
     * @param string $url     The URL to which to make the request
     * @param string $content Content to be sent to the server or null
     * @param string $ctype   The content type
     *
     * @return A multicurl handle
     */
    private function _doAsync(
        string $method,
        string $url,
        ?string $content,
        ?string $ctype
    ) {
        $curl = $this->_do($method, $url, $content, $ctype, false);
        $mh = curl_multi_init();

        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);

        curl_multi_add_handle($mh, $curl);

        do {

            $mrc = curl_multi_exec($mh, $active);
            $mrs = curl_multi_select($mh);

            // not needed because of the usleep(15) below
            // if ($mrs == -1) {
            //     usleep(1);
            // }

            // normal curl takes 400+ ms
            // socket writing takes ~ 100ms but is a lot of code overhead
            // like https://stackoverflow.com/questions/14587514/php-fire-and-forget-post-request
            // this takes ~ 180ms but is simple
            // but weirdly, it only works when running through a proxy
            // without a proxy, we need to wait for $active == 0 (the request to fully process)
            // so we might as well then do a normal curl
            // #TODO make PHP multithread?
            usleep(15);


        } while ($active == 1); //$mrs == 1 && ($mrc == CURLM_CALL_MULTI_PERFORM || $active == 1));

        return $curl;
    }

    /**
     * Do an http/s request
     *
     * @param string $method  One of 'GET', 'POST', etc.
     * @param string $url     The URL to which to make the request
     * @param string $content Content to be sent to the server or null
     * @param string $ctype   The content type
     * @param bool   $execute Whether or not to execute the curl or return the handle
     *
     * @return var An associative array containing 'status', 'content_type', and
     *         'content' or false
     */
    private function _do(
        string $method,
        string $url,
        ?string $content,
        ?string $ctype,
        bool $execute = true
    ) {
        $ret = false;
        $headers = array();
        $response = '';

        $curl = curl_init();

        curl_reset($curl);
        curl_setopt($curl, CURLOPT_USERAGENT, \Ubiq\LIBRARY . '/' . \Ubiq\VERSION);

        curl_setopt($curl, CURLOPT_URL, $url);

        if ($content) {
            array_push($headers, 'Expect:');
            curl_setopt($curl, CURLOPT_UPLOAD, true);
            curl_setopt($curl, CURLOPT_INFILESIZE, strlen($content));
            curl_setopt(
                $curl, CURLOPT_READFUNCTION,
                /* this function will consume $content */
                function ($curl, $rsrc, $length) use (&$content) {
                    $ret = substr($content, 0, $length);
                    $content = substr($content, $length);
                    return $ret;
                }
            );
        }

        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt(
            $curl, CURLOPT_WRITEFUNCTION,
            function ($curl, $data) use (&$response) {
                $response .= $data;
                return strlen($data);
            }
        );

        if ($this->_papi && $this->_sapi) {
            foreach (
                $this->_sign(
                    $method, $url, $content, $ctype
                ) as $k => $v
            ) {
                array_push($headers, $k . ': ' . $v);
            }
        }

        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        if (!$execute) {
            return $curl;
        }

        $this->_curl = $curl;

        curl_exec($this->_curl);
        $i = curl_getinfo($this->_curl);
        $e = curl_error($this->_curl);

        $ret = array(
            'status' => curl_getinfo(
                $this->_curl, CURLINFO_RESPONSE_CODE
            ),
            'content_type' => curl_getinfo(
                $this->_curl, CURLINFO_CONTENT_TYPE
            ),
            'info' => $i,
            'error' => $e,
            'content' => $response
        );

        $ret['success'] = empty($e) && ($ret['status'] == 200 || $ret['status'] == 201);

        return $ret;
    }

    /**
     * Do an http/s GET request
     *
     * @param string $url The URL to which to make the request
     *
     * @return An associative array containing 'status', 'content_type', and
     *         'content' or false
     */
    public function get(string $url)
    {
        return $this->_do('GET', $url, null, null);
    }

    /**
     * Do an http/s POST request
     *
     * @param string $url     The URL to which to make the request
     * @param string $content Content to be sent to the server or null
     * @param string $ctype   The content type
     *
     * @return An associative array containing 'status', 'content_type', and
     *         'content' or false
     */
    public function post(
        string $url, string $content, string $ctype = 'text/plain'
    ) {
        return $this->_do('POST', $url, $content, $ctype);
    }

    /**
     * Do an http/s POST request asyncronously
     *
     * @param string $url     The URL to which to make the request
     * @param string $content Content to be sent to the server or null
     * @param string $ctype   The content type
     *
     * @return An associative array containing 'status', 'content_type', and
     *         'content' or false
     */
    public function postAsync(
        string $url, string $content, string $ctype = 'text/plain'
    ) {
        return $this->_doAsync('POST', $url, $content, $ctype);
    }
    /**
     * Do an http/s PATCH request
     *
     * @param string $url     The URL to which to make the request
     * @param string $content Content to be sent to the server or null
     * @param string $ctype   The content type
     *
     * @return An associative array containing 'status', 'content_type', and
     *         'content' or false
     */
    public function patch(
        string $url, string $content, string $ctype = 'text/plain'
    ) {
        return $this->_do('PATCH', $url, $content, $ctype);
    }

    /**
     * Construct a new http/s object
     *
     * @param string $papi Ubiq client public API key
     * @param string $sapi Ubiq client secret signing key
     */
    public function __construct(string $papi = null, string $sapi = null)
    {
        $this->_papi = $papi;
        $this->_sapi = $sapi;
        $this->_curl = curl_init();
    }

    /**
     * Destroy request object
     */
    public function __destruct()
    {
        curl_close($this->_curl);
    }
}
