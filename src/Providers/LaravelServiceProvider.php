<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean luochuan <luochuan148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth\Providers;

use luochuan\JWTAuth\Http\Parser\Cookies;
use luochuan\JWTAuth\Http\Parser\RouteParams;

class LaravelServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $path = realpath(__DIR__.'/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->aliasMiddleware();

        $this->extendAuthGuard();

        $this->app['luochuan.jwt.parser']->addParser([
            new RouteParams,
            new Cookies($this->config('decrypt_cookies')),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('luochuan.jwt.provider.storage', function () {
            $instance = $this->getConfigInstance('providers.storage');

            if (method_exists($instance, 'setLaravelVersion')) {
                $instance->setLaravelVersion($this->app->version());
            }

            return $instance;
        });
    }

    /**
     * Alias the middleware.
     *
     * @return void
     */
    protected function aliasMiddleware()
    {
        $router = $this->app['router'];

        $method = method_exists($router, 'aliasMiddleware') ? 'aliasMiddleware' : 'middleware';

        foreach ($this->middlewareAliases as $alias => $middleware) {
            $router->$method($alias, $middleware);
        }
    }
}
