<?php namespace Ctrl\Discourse\Sso;

use Symfony\Component\HttpFoundation\ParameterBag;

class Payload extends ParameterBag
{
    /** @var string */
    private $secret;

    /**
     * @param string $secret
     * @param array $parameters
     */
    public function __construct($secret, array $parameters = [])
    {
        $this->secret = $secret;

        parent::__construct($parameters);
    }

    /**
     * Returns the payload as an unsigned queryString.
     *
     * @return string
     */
    public function getUnsigned()
    {
        return $this->buildQuery($this->parameters);
    }

    /**
     * @return string
     */
    public function getQueryString()
    {
        $payload = base64_encode($this->getUnsigned());
        return $this->buildQuery([ 'sso' => $payload, 'sig' => $this->sign($payload) ]);
    }

    /**
     * Builds an » RFC 3986 query string from the given parameters.
     *
     * @param array $params
     * @return string
     */
    private function buildQuery(array $params = [])
    {
        return http_build_query($params, null, null, PHP_QUERY_RFC3986);
    }

    /**
     * @param $payload
     * @return string
     */
    private function sign($payload)
    {
        return hash_hmac('sha256', $payload, $this->secret);
    }

    /**
     * @param string $baseUrl
     * @return string
     */
    public function toUrl($baseUrl)
    {
        $baseUrl = substr($baseUrl, -1, 1) === '?' ? $baseUrl : $baseUrl . '?';

        return $baseUrl . $this->getQueryString();
    }
}
