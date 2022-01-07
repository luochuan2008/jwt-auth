<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) luochuan <156356969@qq.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace luochuan\JWTAuth;

use luochuan\JWTAuth\Contracts\Providers\JWT as JWTContract;
use luochuan\JWTAuth\Exceptions\JWTException;
use luochuan\JWTAuth\Exceptions\TokenBlacklistedException;
use luochuan\JWTAuth\Support\CustomClaims;
use luochuan\JWTAuth\Support\RefreshFlow;

class Manager
{
    use CustomClaims, RefreshFlow;

    /**
     * The provider.
     *
     * @var \luochuan\JWTAuth\Contracts\Providers\JWT
     */
    protected $provider;

    /**
     * The blacklist.
     *
     * @var \luochuan\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * the payload factory.
     *
     * @var \luochuan\JWTAuth\Factory
     */
    protected $payloadFactory;

    /**
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * the persistent claims.
     *
     * @var array
     */
    protected $persistentClaims = [];

    /**
     * Constructor.
     *
     * @param  \luochuan\JWTAuth\Contracts\Providers\JWT  $provider
     * @param  \luochuan\JWTAuth\Blacklist  $blacklist
     * @param  \luochuan\JWTAuth\Factory  $payloadFactory
     *
     * @return void
     */
    public function __construct(JWTContract $provider, Blacklist $blacklist, Factory $payloadFactory)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \luochuan\JWTAuth\Payload  $payload
     *
     * @return \luochuan\JWTAuth\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->provider->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \luochuan\JWTAuth\Token  $token
     * @param  bool  $checkBlacklist
     *
     * @throws \luochuan\JWTAuth\Exceptions\TokenBlacklistedException
     *
     * @return \luochuan\JWTAuth\Payload
     */
    public function decode(Token $token, $checkBlacklist = true)
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
                        ->setRefreshFlow($this->refreshFlow)
                        ->customClaims($payloadArray)
                        ->make();

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \luochuan\JWTAuth\Token  $token
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     *
     * @return \luochuan\JWTAuth\Token
     */
    public function refresh(Token $token, $forceForever = false, $resetClaims = false)
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token, $forceForever);
        }

        // Return the new token
        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make($resetClaims)
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @param  \luochuan\JWTAuth\Token  $token
     * @param  bool  $forceForever
     *
     * @throws \luochuan\JWTAuth\Exceptions\JWTException
     *
     * @return bool
     */
    public function invalidate(Token $token, $forceForever = false)
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token, false)
        );
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @param  \luochuan\JWTAuth\Payload  $payload
     *
     * @return array
     */
    protected function buildRefreshClaims(Payload $payload)
    {
        // Get the claims to be persisted from the payload
        $persistentClaims = collect($payload->toArray())
            ->only($this->persistentClaims)
            ->toArray();

        // persist the relevant claims
        return array_merge(
            $this->customClaims,
            $persistentClaims,
            [
                'sub' => $payload['sub'],
                'iat' => $payload['iat'],
            ]
        );
    }

    /**
     * Get the Payload Factory instance.
     *
     * @return \luochuan\JWTAuth\Factory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance.
     *
     * @return \luochuan\JWTAuth\Contracts\Providers\JWT
     */
    public function getJWTProvider()
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     *
     * @return \luochuan\JWTAuth\Blacklist
     */
    public function getBlacklist()
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     * @param  bool  $enabled
     *
     * @return $this
     */
    public function setBlacklistEnabled($enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setPersistentClaims(array $claims)
    {
        $this->persistentClaims = $claims;

        return $this;
    }
}
