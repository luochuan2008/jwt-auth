<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) luochuan <156356969@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Claims;

class Custom extends Claim
{
    /**
     * @param  string  $name
     * @param  mixed  $value
     *
     * @return void
     */
    public function __construct($name, $value)
    {
        parent::__construct($value);
        $this->setName($name);
    }
}
