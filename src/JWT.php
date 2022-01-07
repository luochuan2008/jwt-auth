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

use BadMethodCallException;
use Illuminate\Http\Request;
use luochuan\JWTAuth\Contracts\JWTSubject;
use luochuan\JWTAuth\Exceptions\JWTException;
use luochuan\JWTAuth\Http\Parser\Parser;
use luochuan\JWTAuth\Support\CustomClaims;

class JWT
{
    use CustomClaims;

    /**
     * The authentication manager.
     *
     * @var \luochuan\JWTAuth\Manager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \luochuan\JWTAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * The token.
     *
     * @var \luochuan\JWTAuth\Token|null
     */
    protected $token;

    /**
     * Lock the subject.
     *
     * @var bool
     */
    protected $lockSubject = true;

    /**
     * JWT constructor.
     *
     * @param  \luochuan\JWTAuth\Manager  $manager
     * @param  \luochuan\JWTAuth\Http\Parser\Parser  $parser
     * @param Request $request
     * @return void
     */
    public function __construct(Manager $manager, Parser $parser)
    {

        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     *
     * @param  \luochuan\JWTAuth\Contracts\JWTSubject  $subject
     *
     * @return string
     */
    public function fromSubject(JWTSubject $subject)
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
     *
     * @param  \luochuan\JWTAuth\Contracts\JWTSubject  $user
     *
     * @return string
     */
    public function fromUser(JWTSubject $user)
    {
        return $this->fromSubject($user);
    }

    /**
     * Refresh an expired token.
     *
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     *
     * @return string
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())
                             ->refresh($this->token, $forceForever, $resetClaims)
                             ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     *
     * @param  bool  $forceForever
     *
     * @return $this
     */
    public function invalidate($forceForever = false)
    {
        $this->requireToken();

        $this->manager->invalidate($this->token, $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @throws \luochuan\JWTAuth\Exceptions\JWTException
     *
     * @return \luochuan\JWTAuth\Payload
     */
    public function checkOrFail()
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     * @param  bool  $getPayload
     *
     * @return \luochuan\JWTAuth\Payload|bool
     */
    public function check($getPayload = false)
    {
        try {
            $payload = $this->checkOrFail();
        } catch (JWTException $e) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     *
     * @return \luochuan\JWTAuth\Token|null
     */
    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (JWTException $e) {
                $this->token = null;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @throws \luochuan\JWTAuth\Exceptions\JWTException
     *
     * @return $this
     */
    public function parseToken()
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JWTException('请求字段里不能没有token');
        }

        return $this->setToken($token);
    }

    /**
     * 从请求里获取token
     * @return $this
     * @throws JWTException
     */
    public function parseTokenFormHeader()
    {
        if(!$this->parser->getRequest()->hasHeader('token')){
            throw new JWTException('请携带令牌访问');
        }
        if (! $token = $this->parser->parseTokenFormHeader()) {
            throw new JWTException('请求头里没有令牌，不能访问');
        }
        return $this->setToken($token);
    }


    /**
     * Get the raw Payload instance.
     *
     * @return \luochuan\JWTAuth\Payload
     */
    public function getPayload()
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
    }

    /**
     * Alias for getPayload().
     *
     * @return \luochuan\JWTAuth\Payload
     */
    public function payload()
    {
        return $this->getPayload();
    }

    /**
     * Convenience method to get a claim value.
     *
     * @param  string  $claim
     *
     * @return mixed
     */
    public function getClaim($claim)
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     *
     * @param  \luochuan\JWTAuth\Contracts\JWTSubject  $subject
     *
     * @return \luochuan\JWTAuth\Payload
     */
    public function makePayload(JWTSubject $subject)
    {
        return $this->factory()->customClaims($this->getClaimsArray($subject))->make();
    }

    /**
     * Build the claims array and return it.
     *
     * @param  \luochuan\JWTAuth\Contracts\JWTSubject  $subject
     *
     * @return array
     */
    protected function getClaimsArray(JWTSubject $subject)
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getJWTCustomClaims(), // custom claims from JWTSubject method
            $this->customClaims // custom claims from inline setter
        );
    }

    /**
     * Get the claims associated with a given subject.
     *
     * @param  \luochuan\JWTAuth\Contracts\JWTSubject  $subject
     *
     * @return array
     */
    protected function getClaimsForSubject(JWTSubject $subject)
    {
        return array_merge([
            'sub' => $subject->getJWTIdentifier(),
        ], $this->lockSubject ? ['prv' => $this->hashSubjectModel($subject)] : []);
    }

    /**
     * Hash the subject model and return it.
     *
     * @param  string|object  $model
     *
     * @return string
     */
    protected function hashSubjectModel($model)
    {
        return sha1(is_object($model) ? get_class($model) : $model);
    }

    /**
     * Check if the subject model matches the one saved in the token.
     *
     * @param  string|object  $model
     *
     * @return bool
     */
    public function checkSubjectModel($model)
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashSubjectModel($model) === $prv;
    }

    /**
     * Set the token.
     *
     * @param  \luochuan\JWTAuth\Token|string  $token
     *
     * @return $this
     */
    public function setToken($token)
    {

        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

        return $this;
    }

    /**
     * Ensure that a token is available.
     *
     * @throws \luochuan\JWTAuth\Exceptions\JWTException
     *
     * @return void
     */
    protected function requireToken()
    {
        if (! $this->token) {
            throw new JWTException('A token is required');
        }
    }

    /**
     * Set the request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Set whether the subject should be "locked".
     *
     * @param  bool  $lock
     *
     * @return $this
     */
    public function lockSubject($lock)
    {
        $this->lockSubject = $lock;

        return $this;
    }

    /**
     * Get the Manager instance.
     *
     * @return \luochuan\JWTAuth\Manager
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return \luochuan\JWTAuth\Http\Parser\Parser
     */
    public function parser()
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     *
     * @return \luochuan\JWTAuth\Factory
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     *
     * @return \luochuan\JWTAuth\Blacklist
     */
    public function blacklist()
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the JWT Manager.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
