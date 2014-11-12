<?php namespace spec\Ctrl\Discourse\Sso;

use Ctrl\Discourse\Sso\QuerySigner;
use Ctrl\Discourse\Sso\SingleSignOn;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SingleSignOnSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Ctrl\Discourse\Sso\SingleSignOn');
    }

    function it_parses_query_parameters(QuerySigner $signer)
    {
        $query = [ 'sso' => 'value', 'sig' => 'sig_value' ];

        $signer->validates($query)->willReturn(true);

        $this->parse($query, $signer)->shouldReturnAnInstanceOf('Ctrl\Discourse\Sso\Payload');
    }

    function it_parses_a_query_string(QuerySigner $signer)
    {
        $query = [ 'sso' => 'value', 'sig' => 'sig_value' ];

        $signer->validates($query)->willReturn(true);

        $this->parse(SingleSignOn::buildQuery($query), $signer)->shouldReturnAnInstanceOf('Ctrl\Discourse\Sso\Payload');
    }

    function it_throws_exceptions_for_invalid_signatures(QuerySigner $signer)
    {
        $query = [ 'sso' => 'value', 'sig' => 'sig_value' ];

        $signer->validates($query)->willReturn(false);

        $this->shouldThrow('\RuntimeException')->duringParse($query, $signer);
    }

    function its_payload_contains_the_nonce(QuerySigner $signer)
    {
        $payload    = SingleSignOn::buildQuery([ 'nonce' => 'some_nonce' ]);
        $sso        = base64_encode($payload);
        $sig        = hash_hmac('sha256', $sso, 'secret');
        $query      = [ 'sso' => $sso, 'sig' => $sig ];

        $signer->validates($query)->willReturn('true');

        $signer->sign($payload)->willReturn($sig);

        $this->parse($query, $signer)->get('nonce')->shouldBeString();
    }
}
