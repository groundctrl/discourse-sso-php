<?php namespace Ctrl\Discourse\Sso;

use Symfony\Component\HttpFoundation\Request;

class SingleSignOn
{
    /**
     * Converts a queryString and signing key into a Payload.
     *
     * @param array|string $query
     * @param string $signingKey
     * @return Payload
     */
    public function parse($query, $signingKey)
    {
        if (is_string($query)) {
            $query = $this->getQueryAsParameters($query);
        }

        if (! $this->validates($query, $signingKey)) {
            throw new \RuntimeException('Bad signature for payload.');
        }

        return new Payload($signingKey, $query);
    }

    /**
     * Returns the queryString as an array of parameters.
     *
     * @param string $queryString
     * @return array
     */
    private function getQueryAsParameters($queryString)
    {
        $params = [];
        parse_str($queryString, $params);
        return $params;
    }

    /**
     * Checks the payload against the signature generated with the secret key.
     *
     * @param array $query
     * @param string $signingKey
     * @return bool
     */
    private function validates(array $query, $signingKey)
    {
        if (! isset ($query['sso'], $query['sig'])) {
            return false;
        }

        $signer = self::getSigningFunction($query['sso']);

        return $signer($signingKey) === $query['sig'];
    }

    /**
     * Builds a normalized query string from the given parameters.
     *
     * @param array $params
     * @return string
     */
    static public function buildQuery(array $params)
    {
        return Request::normalizeQueryString(http_build_query($params, null, '&'));
    }

    /**
     * Returns a function capable of signing the payload when given a signing key.
     *
     * @param string $payload
     * @return callable
     */
    static public function getSigningFunction($payload)
    {
        return function ($key) use ($payload) {
            return hash_hmac('sha256', $payload, $key);
        };
    }
}
