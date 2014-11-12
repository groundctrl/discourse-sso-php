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
        return SingleSignOn::buildQuery($this->parameters);
    }

    /**
     * @return string
     */
    public function getQueryString()
    {
        $payload = base64_encode($this->getUnsigned());

        return SingleSignOn::buildQuery([ 'sso' => $payload, 'sig' => $this->sign($payload) ]);
    }

    /**
     * Signs the payload as HMAC-SHA256.
     *
     * @param $payload
     * @return string
     */
    private function sign($payload)
    {
        $signer = SingleSignOn::getSigningFunction($payload);

        return $signer($this->secret);
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
