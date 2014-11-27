<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\Secret;
use Ctrl\Discourse\Sso\SingleSignOn;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class QuerySignerSpec extends ObjectBehavior
{
    function let(Secret $secret)
    {
        $secret->__toString()->willReturn('secret');

        $this->beConstructedWith($secret);
    }

    function it_validates_query_parameters($secret)
    {
        $data   = SingleSignOn::buildQuery([ 'nonce' => uniqid() ]);
        $sso    = base64_encode($data);
        $sig    = hash_hmac('sha256', $sso, 'secret');

        $secret->sign($sso)->willReturn($sig);

        $sig    = hash_hmac('sha256', $sso, 'secret');
        $query  = [ 'sso' => $sso, 'sig' => $sig ];

        $this->validates($query)->shouldBe(true);
    }

    function it_does_not_validate_on_signature_mismatch()
    {
        $this->beConstructedWith('not_the_secret');

        $data       = SingleSignOn::buildQuery([ 'nonce' => uniqid() ]);
        $sso        = base64_encode($data);
        $sig        = hash_hmac('sha256', $sso, 'secret');
        $payload    = [ 'sso' => $sso, 'sig' => $sig ];

        $this->validates($payload)->shouldBe(false);
    }

    function it_does_not_validate_if_missing_sso()
    {
        $this->validates(SingleSignOn::buildQuery([ 'sig' => 'signature' ]))->shouldBe(false);
    }

    function it_does_not_validate_if_missing_sig()
    {
        $this->validates(SingleSignOn::buildQuery([ 'sso' => 'nonce=payload' ]))->shouldBe(false);
    }
}
