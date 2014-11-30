<?php namespace Ctrl\Discourse\Sso;

class SingleSignOn
{
    const VERSION = '1.0.0';

    /** @var Secret */
    private $secret;

    /**
     * SingleSignOn Constructor.
     *
     * @param string|Secret $key
     */
    public function __construct($key = null)
    {
        if ($key) {
            $this->secret = Secret::create($key);
        }
    }

    /**
     * Converts query string parameters into a Payload.
     *
     * @param mixed $query A query string, or a collection of query parameters.
     * @param Secret $secret
     * @return Payload
     */
    public function parse($query, $secret = null)
    {
        $secret = $secret ? Secret::create($secret) : $this->secret;
        if (null === $secret) {
            throw new \RuntimeException('Secret not set on instance, be sure to pass it on parse.');
        }

        $query = $this->normalize($query);

        if (! SingleSignOn::validates($query, $secret)) {
            throw new \RuntimeException('Bad signature for payload.');
        }

        $data = $this->queryStringToArray(base64_decode($query['sso']));

        return new Payload($data + [ 'sso_secret' => $secret ]);
    }

    /**
     * Normalizes mixed query arguments into a parameter hash.
     *
     * @param mixed $query
     * @return array
     */
    private function normalize($query)
    {
        if (is_array($query)) {
            return $query;
        }

        return $this->queryStringToArray($query);
    }

    /**
     * Returns the queryString as an array of parameters.
     *
     * @param string $query
     * @return array
     */
    private function queryStringToArray($query)
    {
        $params = [];
        $url = parse_url($query);
        $query = isset($url['query']) ? $url['query'] : $url['path'];
        parse_str($query, $params);
        return $params;
    }

    /**
     * Builds a normalized query string from the given parameters.
     *
     * This normalization logic comes direct from Symfony's HttpFoundation Component.
     * Since this is the extent of the dependency, let's opt for a bit of code duplication instead.
     *
     * @param array $params
     * @return string
     */
    static public function buildQuery(array $params)
    {
        $qs = http_build_query($params, null, '&');

        if ('' == $qs) {
            return '';
        }

        $parts = array();
        $order = array();

        foreach (explode('&', $qs) as $param) {
            if ('' === $param || '=' === $param[0]) {
                // Ignore useless delimiters, e.g. "x=y&".
                // Also ignore pairs with empty key, even if there was a value, e.g. "=value", as such nameless values cannot be retrieved anyway.
                // PHP also does not include them when building _GET.
                continue;
            }

            $keyValuePair = explode('=', $param, 2);

            // GET parameters, that are submitted from a HTML form, encode spaces as "+" by default (as defined in enctype application/x-www-form-urlencoded).
            // PHP also converts "+" to spaces when filling the global _GET or when using the function parse_str. This is why we use urldecode and then normalize to
            // RFC 3986 with rawurlencode.
            $parts[] = isset($keyValuePair[1]) ?
                rawurlencode(urldecode($keyValuePair[0])).'='.rawurlencode(urldecode($keyValuePair[1])) :
                rawurlencode(urldecode($keyValuePair[0]));
            $order[] = urldecode($keyValuePair[0]);
        }

        array_multisort($order, SORT_ASC, $parts);

        return implode('&', $parts);
    }

    /**
     * Checks the payload against the signature generated with the secret key.
     *
     * @param array $query
     * @param Secret $secret
     * @return bool
     */
    static public function validates($query, Secret $secret)
    {
        if (! isset ($query['sso'], $query['sig'])) {
            return false;
        }

        return $query['sig'] === $secret->sign($query['sso']);
    }
}
