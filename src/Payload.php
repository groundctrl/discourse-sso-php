<?php namespace Ctrl\Discourse\Sso;

use Symfony\Component\HttpFoundation\ParameterBag;

class Payload extends ParameterBag
{
    /** @var string */
    private $secret;

    /** @var array */
    private $predefined = [ 'nonce', 'name', 'username', 'email', 'external_id',
        'avatar_url', 'avatar_force_update', 'about_me', 'external_id'
    ];

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
     * {@inheritDoc}
     */
    public function add(array $parameters = array())
    {
        $params = [];
        foreach ($parameters as $key => $value) {
            $pKey = $this->prefix($key);
            $params[$pKey] = $value;
        }

        parent::add($params);
    }

    /**
     * {@inheritDoc}
     */
    public function set($key, $value)
    {
        parent::set($this->prefix($key), $value);
    }

    /**
     * Prefixes a parameter with "custom." if the parameter is not predefined.
     *
     * @param string $key
     * @return string
     */
    private function prefix($key)
    {
        return ! in_array($key, $this->predefined) ? 'custom.' . $key : $key;
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
