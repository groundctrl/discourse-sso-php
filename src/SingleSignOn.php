<?php namespace Ctrl\Discourse\Sso;

use Symfony\Component\HttpFoundation\Request;

class SingleSignOn
{
    /**
     * Converts query string parameters into a Payload.
     *
     * @param $query
     * @param QuerySigner $signer
     * @return Payload
     */
    public function parse($query, QuerySigner $signer)
    {
        if (is_string($query)) {
            $query = $this->getQueryAsParameters($query);
        }

        if (! $signer->validates($query)) {
            throw new \RuntimeException('Bad signature for payload.');
        }

        return new Payload($signer, $this->getQueryAsParameters(base64_decode($query['sso'])));
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
     * Builds a normalized query string from the given parameters.
     *
     * @param array $params
     * @return string
     */
    static public function buildQuery(array $params)
    {
        return Request::normalizeQueryString(http_build_query($params, null, '&'));
    }
}
