<?php namespace spec\Ctrl\Discourse\Sso;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class PayloadSpec extends ObjectBehavior
{
    static public $specKey = 'S1gN!nGk3Y';

    function let()
    {
        $this->beConstructedWith(self::$specKey, [
            'nonce' => 'nonce',
        ]);
    }

    function it_is_a_parameter_bag()
    {
        $this->shouldHaveType('Symfony\Component\HttpFoundation\ParameterBag');
    }

    function it_gets_an_unsigned_payload()
    {
        $this->getUnsigned()->shouldBuildQueryString([ 'nonce' => 'nonce' ]);
    }

    function it_gets_a_query_string()
    {
        $params     = [ 'nonce' => 'nonce' ];
        $unsigned   = http_build_query($params, null, null, PHP_QUERY_RFC3986);
        $encoded    = base64_encode($unsigned);
        $signed     = hash_hmac('sha256', $encoded, self::$specKey);

        $this->getQueryString()->shouldBuildQueryString([ 'sso' => $encoded, 'sig' => $signed ]);
    }

    function it_can_be_converted_to_a_url()
    {
        $this->toUrl('http://s.discourse')->shouldBe('http://s.discourse?' . $this->getQueryString()->getWrappedObject());
    }

    /**
     * Custom Matchers:
     *
     * - buildQueryString: Checks a method that returns a queryString against an array of values.
     *
     * @return array
     */
    public function getMatchers()
    {
        return [
            'buildQueryString' => function($subject, $params) {
                return $subject === http_build_query($params, null, null, PHP_QUERY_RFC3986);
            },
        ];
    }
}
