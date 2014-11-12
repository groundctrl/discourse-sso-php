<?php namespace Ctrl\Discourse\Sso;

class QuerySigner
{
    private $secret;

    /**
     * @param string $secret
     */
    public function __construct($secret)
    {
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
        return hash_hmac('sha256', $payload, $this->secret);
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

        return $query['sig'] === $this->sign($query['sso']);
    }
}
