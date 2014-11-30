<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\Secret;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SecretSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('my_secret_key');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('Ctrl\Discourse\Sso\Secret');
    }

    function it_signs_a_payload_hmac_sha256()
    {
        $payload = 'my_unsigned_data';

        $this->sign($payload)->shouldBe(hash_hmac(Secret::METHOD, $payload, 'my_secret_key'));
    }

    function it_can_be_cast_to_string()
    {
        $this->__toString()->shouldBe('my_secret_key');
    }

    function it_can_be_instantiated_with_create()
    {
        $this->beConstructedThrough('create', [ 'another_secret_key' ]);

        $this->__toString()->shouldBe('another_secret_key');
    }

    function it_returns_an_existing_secret_on_create(Secret $secret)
    {
        $this->beConstructedThrough('create', [ $secret ]);
        $this->shouldBe($secret);
    }
}
