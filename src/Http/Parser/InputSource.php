<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) luochuan <156356969@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use luochuan\JWTAuth\Contracts\Http\Parser as ParserContract;

class InputSource implements ParserContract
{
    use KeyTrait;

    /**
     * Try to parse the token from the request input source.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        return $request->input($this->key);
    }
}
