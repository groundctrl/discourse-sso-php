<?php namespace Ctrl\Discourse\Sso;

class QueryString extends DataObject
{
    /**
     * Checks the validity of this QueryString's against a secret key.
     *
     * @param string|Secret $key
     * @return bool
     */
    public function isValid($key)
    {
        if (! isset ($this['sso'], $this['sig'])) {
            return false;
        }

        return $this['sig'] === Secret::create($key)->sign($this['sso']);
    }

    /**
     * Creates a QueryString from an array of parameters.
     *
     * @param array $data
     * @return QueryString
     */
    static public function fromArray(array $data = [])
    {
        return new QueryString($data);
    }

    /**
     * Creates a QueryString from a string.
     *
     * @param string $query A url or query string part.
     * @param array $data An optional data array.
     * @return QueryString
     */
    public static function fromString($query, array $data = [])
    {
        $url = parse_url($query);
        $query = isset($url['query']) ? $url['query'] : $url['path'];
        parse_str($query, $data);

        return new QueryString($data);
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
    static public function normalize(array $params)
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
}
