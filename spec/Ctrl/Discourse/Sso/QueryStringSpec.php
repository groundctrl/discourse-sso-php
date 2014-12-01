<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\QueryString;
use Ctrl\Discourse\Sso\Secret;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class QueryStringSpec extends ObjectBehavior
{
    function let(Secret $secret)
    {
        $key = 'secret';
        $secret->__toString()->willReturn($key);

        $secret->sign(Argument::type('string'))->will(function($args) use ($key) {
            return hash_hmac(Secret::METHOD, $args[0], $key);
        });
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('Ctrl\Discourse\Sso\QueryString');
    }

    function it_behaves_like_an_array()
    {
        $this->shouldHaveType('\ArrayAccess');
    }

    function it_can_be_constructed_from_a_string()
    {
        $this->beConstructedThrough('fromString', [ 'nonce=abcdefg']);

        $this->offsetGet('nonce')->shouldBe('abcdefg');
    }

    function it_can_be_created_from_an_array()
    {
        $this->beConstructedThrough('fromArray', [ [ 'foo' => 'bar' ] ]);

        $this->offsetGet('foo')->shouldBe('bar');
    }

    function it_is_countable()
    {
        $this->beConstructedWith([ 'a' => '1', 'b' => 2 ]);
        $this->shouldHaveCount(2);
    }

    function it_can_be_cast_to_a_normalized_string()
    {
        $this->beConstructedWith([ 'c' => 'foo', 'a' => 'bar', 'b' => 'bat' ]);
        $this->__toString()->shouldBe('a=bar&b=bat&c=foo');
    }

    function it_validates_query_parameters(Secret $secret)
    {
        $data   = QueryString::normalize([ 'nonce' => uniqid() ]);
        $sso    = base64_encode($data);
        $sig    = hash_hmac(Secret::METHOD, $sso, (string)$secret->getWrappedObject());
        $query  = [ 'sso' => $sso, 'sig' => $sig ];

        $this->beConstructedThrough('fromArray', [ $query ]);

        $this->isValid($secret)->shouldBe(true);
    }

    function it_does_not_validate_if_missing_sso(Secret $secret)
    {
        $this->beConstructedThrough('fromArray', [ [ 'sso' => 'abcdefg' ] ]);

        $this->isValid($secret)->shouldBe(false);
    }

    function it_does_not_validate_if_missing_sig(Secret $secret)
    {
        $this->beConstructedThrough('fromArray', [ [ 'sig' => 'signature' ] ]);

        $this->isValid($secret)->shouldBe(false);
    }
}
