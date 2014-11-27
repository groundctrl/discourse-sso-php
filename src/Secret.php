<?php namespace Ctrl\Discourse\Sso;

/**
 * Secret key for signing requests.
 */
class Secret
{
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
        return hash_hmac('sha256', $payload, $this->key);
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
}
