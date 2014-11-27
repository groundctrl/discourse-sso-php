<?php namespace spec\Ctrl\Discourse\Sso;

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

        $this->sign($payload)->shouldBe(hash_hmac('sha256', $payload, 'my_secret_key'));
    }

    function it_can_be_cast_to_string()
    {
        $this->__toString()->shouldBe('my_secret_key');
    }
}
