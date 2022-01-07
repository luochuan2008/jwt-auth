<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) luochuan <156356969@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Http\Middleware;

use Closure;

/** @deprecated */
class Authenticate extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     *
     * @throws \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        //验证权限是否通过
//        $this->authenticate($request); //从request表单里获取token，键名为token
        $this->authenticateFormHeader($request); //从请求头里获取token，键名token

        return $next($request);
    }
}
