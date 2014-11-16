<?php namespace Ctrl\Discourse\Sso;

class Payload implements \IteratorAggregate, \Countable
{
    /** @var QuerySigner */
    private $signer;

    /** @var array */
    private $parameters;

    /** @var array */
    private $predefined = [ 'nonce', 'name', 'username', 'email', 'external_id',
        'avatar_url', 'avatar_force_update', 'about_me', 'external_id'
    ];

    /**
     * Payload Constructor.
     *
     * @param QuerySigner $signer
     * @param array $parameters
     */
    public function __construct(QuerySigner $signer, array $parameters = [])
    {
        $this->signer = $signer;

        $this->parameters = $this->remapKeys($parameters);
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

        return SingleSignOn::buildQuery([ 'sso' => $payload, 'sig' => $this->signer->sign($payload) ]);
    }

    /**
     * @return array
     */
    public function all()
    {
        return $this->parameters;
    }

    /**
     * {@inheritDoc}
     */
    public function add(array $parameters = [])
    {
        $this->parameters = array_replace($this->parameters, $this->remapKeys($parameters));
    }

    /**
     * {@inheritDoc}
     */
    public function set($key, $value)
    {
        $this->parameters[ $this->prefix($key) ] = $value;
    }

    /**
     * Remaps array keys for custom parameters.
     *
     * @param array $parameters
     * @return array
     */
    private function remapKeys(array $parameters)
    {
        $keys = array_map(function($key) { return $this->prefix($key); }, array_keys($parameters));

        return array_combine($keys, array_values($parameters));
    }

    /**
     * Prefixes a parameter with "custom." if the parameter is not predefined.
     *
     * @param string $key
     * @return string
     */
    private function prefix($key)
    {
        return ( in_array($key, $this->predefined) || 'custom.' === substr($key, 0, 7) ) ? $key : 'custom.' . $key;
    }

    /**
     * @param string $baseUrl
     * @return string
     */
    public function toUrl($baseUrl)
    {
        return $baseUrl . ( false === (strpos($baseUrl, '?')) ? '?' : '' ) . $this->getQueryString();
    }

    /**
     * {@inheritDoc}
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->parameters);
    }

    /**
     * {@inheritDoc}
     */
    public function count()
    {
        return count($this->parameters);
    }
}
