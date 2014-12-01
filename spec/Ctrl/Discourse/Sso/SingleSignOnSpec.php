<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\QueryString;
use Ctrl\Discourse\Sso\Secret;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SingleSignOnSpec extends ObjectBehavior
{
    function let(Secret $secret)
    {
        $key = 'secret';
        $secret->__toString()->willReturn($key);

        $secret->sign(Argument::type('string'))->will(function($args) use ($key) {
            return hash_hmac(Secret::METHOD, $args[0], $key);
        });

        $this->beConstructedWith($secret);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('Ctrl\Discourse\Sso\SingleSignOn');
    }

    function it_does_not_validate_on_signature_mismatch($secret)
    {
        $notTheSecret = Secret::create('not_the_secret');
        $this->beConstructedWith($notTheSecret);

        $data   = QueryString::normalize([ 'nonce' => uniqid() ]);
        $sso    = base64_encode($data);
        $sig    = hash_hmac('sha256', $sso, (string)$secret->getWrappedObject());
        $query  = [ 'sso' => $sso, 'sig' => $sig ];

        $this->shouldThrow('\RuntimeException')->duringParse($query);
    }

    function it_throws_exceptions_for_invalid_signatures()
    {
        $query = [ 'sso' => 'value', 'sig' => 'sig_value' ];

        $this->shouldThrow('\RuntimeException')->duringParse($query);
    }

    function it_parses_a_query_string($secret)
    {
        $this->beConstructedWith($secret);

        $data   = QueryString::normalize([ 'nonce' => uniqid() ]);
        $sso    = base64_encode($data);
        $sig    = hash_hmac('sha256', $sso, (string)$secret->getWrappedObject());
        $query  = [ 'sso' => $sso, 'sig' => $sig ];

        $this->parse(QueryString::normalize($query))->shouldReturnAnInstanceOf('Ctrl\Discourse\Sso\Payload');
    }

    function it_parses_a_url_string($secret)
    {
        $data   = QueryString::normalize([ 'nonce' => uniqid() ]);
        $sso    = base64_encode($data);
        $sig    = hash_hmac('sha256', $sso, (string)$secret->getWrappedObject());
        $params = [ 'sso' => $sso, 'sig' => $sig ];
        $query  = 'http://example.com/discourse/sso_login?' . QueryString::normalize($params);

        $this->parse($query)->shouldReturnAnInstanceOf('Ctrl\Discourse\Sso\Payload');
    }

    function its_payload_contains_the_nonce($secret)
    {
        $payload    = QueryString::normalize([ 'nonce' => 'some_nonce' ]);
        $sso        = base64_encode($payload);
        $sig        = hash_hmac('sha256', $sso, 'secret');
        $query      = [ 'sso' => $sso, 'sig' => $sig ];

        $secret->sign($payload)->willReturn($sig);

        $this->parse($query, $secret)->all()->shouldHaveKey('nonce');
    }
}
