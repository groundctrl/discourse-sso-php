<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\QuerySigner;
use Ctrl\Discourse\Sso\Secret;
use Ctrl\Discourse\Sso\SingleSignOn;
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
        $this->getUnsigned()->shouldBe(SingleSignOn::buildQuery([ 'nonce' => 'nonce' ]));
    }

    function it_sets_a_required_parameter()
    {
        $this->set('username', 'specuser');

        $this->getUnsigned()->shouldBe(SingleSignOn::buildQuery([ 'nonce' => 'nonce', 'username' => 'specuser' ]));
    }

    function it_adds_required_parameters()
    {
        $params = [
            'username'      => 'specuser',
            'email'         => 'specuser@example.org',
            'external_id'   => rand(1, 999),
        ];

        $this->add($params);

        $this->getUnsigned()->shouldBe(SingleSignOn::buildQuery($params + [ 'nonce' => 'nonce' ]));
    }

    function it_prefixes_custom_parameters_on_set()
    {
        $this->set('foo', 'bar');

        $this->getUnsigned()->shouldBe(SingleSignOn::buildQuery([ 'nonce' => 'nonce', 'custom.foo' => 'bar' ]));
    }

    function it_prefixes_custom_parameters_on_add()
    {
        $this->add([
            'username' => 'specuser',
            'foos' => 'bars'
        ]);

        $this->getUnsigned()->shouldBe(SingleSignOn::buildQuery([
            'nonce' => 'nonce',
            'username' => 'specuser',
            'custom.foos' => 'bars'
        ]));
    }

    function it_does_not_double_prefix_custom_keys()
    {
        $params = [ 'email' => 'spec@example.com', 'custom.user_url' => 'http://example.com' ];

        $this->add($params);

        $this->getUnsigned()->shouldBe(SingleSignOn::buildQuery($params + [ 'nonce' => 'nonce' ]));
    }

    function it_requires_a_secret_key_to_create_a_query_string()
    {
        $this->beConstructedWith([ 'nonce' => 'nonce' ]);

        $this->shouldThrow()->duringGetQueryString();
    }

    function it_accepts_a_special_sso_secret_parameter_on_construct(Secret $secret)
    {
        $this->beConstructedWith([ 'nonce' => 'nonce', 'sso_secret' => $secret ]);

        $this->shouldHaveCount(1);

        $this->all()->shouldHaveKey('nonce');
    }

    function it_accepts_set_sso_secret(Secret $secret)
    {
        $this->set('sso_secret', $secret);

        $this->shouldHaveCount(1);
    }

    function it_gets_a_query_string(Secret $secret)
    {
        $this->setSecret($secret);

        $payload = SingleSignOn::buildQuery([ 'nonce' => 'nonce' ]);
        $sso = base64_encode($payload);

        $secret->sign($sso)->shouldBeCalled()->willReturn('signature');

        $this->getQueryString()->shouldBe(SingleSignOn::buildQuery([ 'sso' => $sso, 'sig' => 'signature' ]));
    }

    function it_can_be_converted_to_a_url(Secret $secret)
    {
        $this->setSecret($secret);

        $realQueryString = $this->getQueryString()->getWrappedObject();

        $this->toUrl('http://s.discourse')->shouldBe('http://s.discourse?' . $realQueryString);
    }
}
