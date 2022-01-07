<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean luochuan <luochuan148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Contracts;

interface JWTSubject
{
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier();

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims();
}
