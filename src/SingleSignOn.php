<?php namespace Ctrl\Discourse\Sso;

class SingleSignOn
{
    const VERSION = '1.0.0';

    /** @var Secret */
    private $secret;

    /**
     * SingleSignOn Constructor.
     *
     * @param string|Secret $key
     */
    public function __construct($key = null)
    {
        if ($key) {
            $this->secret = Secret::create($key);
        }
    }

    /**
     * Converts query string parameters into a Payload.
     *
     * @param mixed $query A query string, or a collection of query parameters.
     * @param Secret $secret
     * @return Payload
     */
    public function parse($query, $secret = null)
    {
        $secret = $secret ? Secret::create($secret) : $this->secret;
        if (null === $secret) {
            throw new \RuntimeException('Secret not set on instance, be sure to pass it on parse.');
        }

        $query = is_array($query) ? new QueryString($query) : QueryString::fromString($query);

        if (! $query->isValid($secret)) {
            throw new \RuntimeException('Bad signature for payload.');
        }

        $data = QueryString::fromString(base64_decode($query['sso']));

        return new Payload($data->all() + [ 'sso_secret' => $secret ]);
    }
}
