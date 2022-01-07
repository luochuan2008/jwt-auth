<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) luochuan <156356969@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Contracts\Providers;

interface JWT
{
    /**
     * @param  array  $payload
     *
     * @return string
     */
    public function encode(array $payload);

    /**
     * @param  string  $token
     *
     * @return array
     */
    public function decode($token);
}
