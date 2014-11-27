<?php namespace Ctrl\Discourse\Sso;

class QuerySigner
{
    /** @var Secret */
    private $secret;

    /**
     * QuerySigner Constructor.
     *
     * @param string|Secret $secret
     */
    public function __construct($secret)
    {
        if (! $secret instanceof Secret) {
            $secret = new Secret($secret);
        }

        $this->secret = $secret;
    }

    /**
     * Computes the HMAC-SHA256 hash for the given payload.
     *
     * @param string $payload
     * @return string A string representing the result of performing the hash function on the payload.
     */
    public function sign($payload)
    {
        return $this->secret->sign($payload);
    }

    /**
     * Checks the payload against the signature generated with the secret key.
     *
     * @param array $query
     * @return bool
     */
    public function validates($query)
    {
        if (! isset ($query['sso'], $query['sig'])) {
            return false;
        }

        return $query['sig'] === $this->secret->sign($query['sso']);
    }
}
