<?php namespace Ctrl\Discourse\Sso;

/**
 * Secret is a key for signing requests.
 */
class Secret
{
    const METHOD = 'sha256';

    /** @var string */
    private $key;

    /**
     * Secret Constructor.
     *
     * @param string $key
     */
    public function __construct($key)
    {
        $this->key = $key;
    }

    /**
     * Computes the HMAC-SHA256 hash for the given payload with this secret key.
     *
     * @param string $payload
     * @return string The signed payload.
     */
    public function sign($payload)
    {
        return hash_hmac(Secret::METHOD, $payload, $this->key);
    }

    /**
     * Casts this key back to a string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->key;
    }

    /**
     * Factory method for creating Secrets.
     *
     * @param $key
     * @return Secret
     */
    public static function create($key)
    {
        return $key instanceof Secret ? $key : new Secret($key);
    }
}
