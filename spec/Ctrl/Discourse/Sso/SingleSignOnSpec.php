<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\SingleSignOn;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SingleSignOnSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Ctrl\Discourse\Sso\SingleSignOn');
    }

    function it_parses_query_parameters()
    {
        list ($query, $secret) = SsoHelper::getSignedValues('query_params_secret');

        $this->parse($query, $secret)->shouldReturnAnInstanceOf('Ctrl\Discourse\Sso\Payload');
    }

    function it_parses_a_query_string()
    {
        list ($query, $secret) = SsoHelper::getSignedValues('query_string_secret');

        $query = SingleSignOn::buildQuery($query);

        $this->parse($query, $secret)->shouldReturnAnInstanceOf('Ctrl\Discourse\Sso\Payload');
    }

    function it_throws_exceptions_for_signature_mismatch()
    {
        list ($query) = SsoHelper::getSignedValues('theSecretKey');

        $this->shouldThrow('\RuntimeException')->duringParse($query, 'notTheSecretKey');
    }

    function it_parses_valid_payloads()
    {
        list ($query, $secret) = SsoHelper::getSignedValues('parse_valid_secret');

        $this->parse($query, $secret)->shouldReturnAnInstanceOf('Ctrl\Discourse\Sso\Payload');
    }
}

class SsoHelper
{
    public static function getSignedValues($secret)
    {
        $payload    = SingleSignOn::buildQuery([ 'nonce' => uniqid() ]);
        $sso        = base64_encode($payload);
        $sig        = hash_hmac('sha256', $sso, $secret);
        $query      = [ 'sso' => $sso, 'sig' => $sig ];

        return [ $query, $secret, $payload, $sso, $sig ];
    }
}
