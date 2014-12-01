<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\QueryString;
use Ctrl\Discourse\Sso\Secret;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class PayloadSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith([ 'nonce' => 'nonce' ]);
    }

    function it_gets_an_unsigned_payload()
    {
        $this->getUnsigned()->shouldBe(QueryString::normalize([ 'nonce' => 'nonce' ]));
    }

    function it_sets_a_required_parameter()
    {
        $this->set('username', 'specuser');

        $this->getUnsigned()->shouldBe(QueryString::normalize([ 'nonce' => 'nonce', 'username' => 'specuser' ]));
    }

    function it_adds_required_parameters()
    {
        $params = [
            'username'      => 'specuser',
            'email'         => 'specuser@example.org',
            'external_id'   => rand(1, 999),
        ];

        $this->add($params);

        $this->getUnsigned()->shouldBe(QueryString::normalize($params + [ 'nonce' => 'nonce' ]));
    }

    function it_prefixes_custom_parameters_on_set()
    {
        $this->set('foo', 'bar');

        $this->getUnsigned()->shouldBe(QueryString::normalize([ 'nonce' => 'nonce', 'custom.foo' => 'bar' ]));
    }

    function it_prefixes_custom_parameters_on_add()
    {
        $this->add([
            'username' => 'specuser',
            'foos' => 'bars'
        ]);

        $this->getUnsigned()->shouldBe(QueryString::normalize([
            'nonce' => 'nonce',
            'username' => 'specuser',
            'custom.foos' => 'bars'
        ]));
    }

    function it_requires_a_secret_key_to_create_a_query_string()
    {
        $this->beConstructedWith([ 'nonce' => 'nonce' ]);

        $this->shouldThrow()->duringGetQueryString();
    }

    function it_gets_a_query_string(Secret $secret)
    {
        $this->set('sso_secret', $secret);

        $payload = QueryString::normalize([ 'nonce' => 'nonce' ]);
        $sso = base64_encode($payload);

        $secret->sign($sso)->shouldBeCalled()->willReturn('signature');

        $this->getQueryString()->shouldBe(QueryString::normalize([ 'sso' => $sso, 'sig' => 'signature' ]));
    }

    function it_can_be_converted_to_a_url(Secret $secret)
    {
        $this->beConstructedWith([ 'nonce' => 'nonce', 'sso_secret' => $secret ]);

        $realQueryString = $this->getQueryString()->getWrappedObject();

        $this->toUrl('http://s.discourse')->shouldBe('http://s.discourse?' . $realQueryString);
    }

    function it_works_with_base_url_query_strings(Secret $secret)
    {
        $this->beConstructedWith([ 'nonce' => 'nonce', 'sso_secret' => $secret ]);

        $realQueryString = $this->getQueryString()->getWrappedObject();

        $this->toUrl('http://s.discourse?foo=bar')->shouldBe('http://s.discourse?foo=bar&' . $realQueryString);
    }
}
