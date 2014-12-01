<?php namespace Ctrl\Discourse\Sso;

class Payload extends DataObject
{
    /** @var array */
    private $accessors = [ 'nonce', 'name', 'username', 'email', 'external_id',
        'avatar_url', 'avatar_force_update', 'about_me', 'return_sso_url'
    ];

    /** @var array */
    private $attributes = [ 'sso_secret', 'sso_url' ];

    /** @var array */
    private $reserved = [];

    /** @var array */
    private $customFields = [];

    /**
     * Payload Constructor.
     *
     * @param array $parameters
     */
    public function __construct(array $parameters = [])
    {
        $this->reserved = array_merge($this->accessors, $this->attributes);

        $this->resolveCustom($parameters);

        parent::__construct($parameters);
    }

    /**
     * Returns the payload as an unsigned queryString.
     *
     * @return string
     */
    public function getUnsigned()
    {
        $payload = [];

        foreach ($this->data as $key => $value) {
            if (in_array($key, $this->accessors)) {
                $payload[$key] = $value;
            } elseif (in_array($key, $this->customFields)) {
                $payload['custom.'.$key] = $value;
            }
        }

        return QueryString::normalize($payload);
    }

    /**
     * @return string
     */
    public function getQueryString()
    {
        if (! isset ($this->data['sso_secret'])) {
            throw new \RuntimeException('No secret key defined for this payload.');
        }

        $secret = Secret::create($this->data['sso_secret']);
        $payload = base64_encode($this->getUnsigned());

        return QueryString::normalize([ 'sso' => $payload, 'sig' => $secret->sign($payload) ]);
    }

    /**
     * {@inheritDoc}
     */
    public function add(array $parameters = [])
    {
        $this->resolveCustom($parameters);

        $this->data = array_replace($this->data, $parameters);
    }

    /**
     * {@inheritDoc}
     */
    public function set($key, $value)
    {
        $this->resolveCustom($key);

        $this->data[$key] = $value;
    }

    /**
     * Returns the payload data as a query string, appended to the provided url.
     *
     * @param string $baseUrl
     * @return string
     */
    public function toUrl($baseUrl = '')
    {
        return $baseUrl . ( false !== (strpos($baseUrl, '?')) ? '&' : '?' ) . $this->getQueryString();
    }

    /**
     * Adds the key to the customFields array, unless the key is a reserved one.
     *
     * @param string|array $key
     */
    private function resolveCustom($key)
    {
        if (is_array($key)) {
            foreach ($key as $k => $v) {
                $this->resolveCustom($k);
            }
        } else {
            if (! in_array($key, $this->reserved)) {
                $this->customFields[] = $key;
            }
        }
    }
}
