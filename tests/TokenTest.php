<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean luochuan <luochuan148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Test;

use luochuan\JWTAuth\Token;

class TokenTest extends AbstractTestCase
{
    /**
     * @var \luochuan\JWTAuth\Token
     */
    protected $token;

    public function setUp(): void
    {
        parent::setUp();

        $this->token = new Token('foo.bar.baz');
    }

    /** @test */
    public function it_should_return_the_token_when_casting_to_a_string()
    {
        $this->assertEquals((string) $this->token, $this->token);
    }

    /** @test */
    public function it_should_return_the_token_when_calling_get_method()
    {
        $this->assertIsString($this->token->get());
    }
}
