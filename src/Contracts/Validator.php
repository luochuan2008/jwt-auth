<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) luochuan <156356969@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Contracts;

interface Validator
{
    /**
     * Perform some checks on the value.
     *
     * @param  mixed  $value
     *
     * @return void
     */
    public function check($value);

    /**
     * Helper function to return a boolean.
     *
     * @param  array  $value
     *
     * @return bool
     */
    public function isValid($value);
}
