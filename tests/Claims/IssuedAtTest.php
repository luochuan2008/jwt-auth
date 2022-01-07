<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) luochuan <156356969@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Test\Claims;

use luochuan\JWTAuth\Claims\IssuedAt;
use luochuan\JWTAuth\Exceptions\InvalidClaimException;
use luochuan\JWTAuth\Test\AbstractTestCase;

class IssuedAtTest extends AbstractTestCase
{
    /** @test */
    public function it_should_throw_an_exception_when_passing_a_future_timestamp()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [iat]');

        new IssuedAt($this->testNowTimestamp + 3600);
    }
}
