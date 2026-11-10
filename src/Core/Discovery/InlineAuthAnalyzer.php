<?php

declare(strict_types=1);

namespace ApiPosture\Core\Discovery;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;

/**
 * Judges whether a block of code (middleware handle(), controller action, helper, route closure,
 * FormRequest::authorize()) enforces authentication, from what it does rather than what it is called.
 *
 * A rejection counts as authentication when:
 *  - it is a 401/403 (status, abort, exception) and the code inspects the caller's identity
 *    (auth user/guard, Gate, hash_equals, JWT decode, signed URL), or
 *  - it is a 401 and the code reads a credential (any request header, a credential-named
 *    input such as api_key/token, or a validator called with the request).
 *
 * A 401/403 that only compares business data (an appointment has an invoice, two
 * request-supplied ids match, a plan header says "expired") is not authentication.
 */
final class InlineAuthAnalyzer
{
    /** Exceptions that signal "not authenticated" (lower-case short names). */
    private const UNAUTHENTICATED_EXCEPTIONS = [
        'authenticationexception', 'unauthorizedexception', 'unauthorizedhttpexception',
        'authenticationcredentialsnotfoundexception', 'badcredentialsexception',
        'tokeninvalidexception', 'tokenexpiredexception', 'invalidsignatureexception',
    ];

    /** Exceptions that signal "forbidden" (lower-case short names). */
    private const FORBIDDEN_EXCEPTIONS = [
        'accessdeniedhttpexception', 'authorizationexception', 'accessdeniedexception',
    ];

    /** Method calls that inspect the caller's identity or a signature. */
    private const IDENTITY_CALLS = ['user', 'guard', 'bearertoken', 'check', 'guest', 'session', 'authenticate', 'hasvalidsignature', 'hasvalidrelativesignature', 'unauthenticated'];
    private const IDENTITY_FUNCTIONS = ['auth', 'hash_equals', 'hash_hmac', 'password_verify'];
    /** Static facades/classes whose calls inspect identity, secrets or tokens. */
    private const IDENTITY_CLASSES = ['auth', 'gate', 'hash', 'jwt', 'jwtauth', 'jwtmanager', 'passport', 'sanctum'];

    /** Request accessors whose argument names the value being read. */
    private const REQUEST_ACCESSORS = ['input', 'get', 'query', 'post', 'json', 'string', 'cookie', 'route'];
    private const HEADER_ACCESSORS = ['header', 'hasheader'];

    /** Names of request values that carry credentials. */
    private const CREDENTIAL_NAME = '/(token|secret|signature|password|passwd|jwt|api[-_]?key|apikey|auth[-_]?key|authorization)/i';

    /** Names of calls that validate the caller (GatewayHandshake::isValid($request), $signer->verify($request)). */
    private const VALIDATOR_NAME = '/^(is[-_]?valid|valid|verif|authenticat|authoriz|signature|handshake)/i';

    private NodeFinder $finder;

    public function __construct()
    {
        $this->finder = new NodeFinder();
    }

    /**
     * @param Node[] $stmts
     */
    public function enforcesAuth(array $stmts): bool
    {
        $unauthenticated = $this->finder->findFirst($stmts, fn(Node $n) => $this->isUnauthenticatedSignal($n)) !== null;
        $forbidden = $this->finder->findFirst($stmts, fn(Node $n) => $this->isForbiddenSignal($n)) !== null;

        if (!$unauthenticated && !$forbidden) {
            return false;
        }
        if ($this->inspectsIdentity($stmts)) {
            return true;
        }
        return $unauthenticated && $this->readsCredential($stmts);
    }

    /**
     * A route closure whose body does nothing but reject (abort(403), throw, return a 4xx response):
     * the URL is reserved, not served, so nothing behind it is reachable.
     *
     * @param Node[] $stmts
     */
    public function deniesAll(array $stmts): bool
    {
        $first = null;
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Nop) {
                continue;
            }
            $first = $stmt;
            break;
        }
        if ($first === null) {
            return false;
        }
        if ($first instanceof Stmt\Expression) {
            return $this->isRejection($first->expr);
        }
        if ($first instanceof Stmt\Return_ && $first->expr !== null) {
            return $this->isRejection($first->expr);
        }
        // php-parser 4 represents throw as a statement
        return $first instanceof Stmt\Throw_;
    }

    public function isRejection(Expr $expr): bool
    {
        if ($expr instanceof Expr\Throw_) {
            return true;
        }
        if ($expr instanceof Expr\FuncCall && $expr->name instanceof Node\Name && !$expr->isFirstClassCallable()) {
            $name = strtolower($expr->name->getLast());
            $args = $expr->getArgs();
            if ($name === 'abort') {
                return isset($args[0]) && $this->isClientErrorStatus($args[0]->value);
            }
            // response('...', 403) / response()->json(...) is handled below via the status argument
            if ($name === 'response') {
                return isset($args[1]) && $this->isClientErrorStatus($args[1]->value);
            }
            return false;
        }
        // response()->json([...], 403), new JsonResponse([...], 403), new Response('', 404)
        if (($expr instanceof Expr\MethodCall || $expr instanceof Expr\New_) && !$expr->isFirstClassCallable()) {
            if ($expr instanceof Expr\MethodCall && !$this->isResponseFactoryCall($expr)) {
                return false;
            }
            foreach ($expr->getArgs() as $arg) {
                if ($this->isClientErrorStatus($arg->value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Whether FormRequest::authorize() can deny the request: it has a return that is not the literal true.
     */
    public function authorizeMethodDenies(Stmt\ClassMethod $authorize): bool
    {
        $returns = $this->finder->findInstanceOf($authorize->stmts ?? [], Stmt\Return_::class);
        if ($returns === []) {
            return false;
        }
        foreach ($returns as $return) {
            if (!$return->expr instanceof Expr\ConstFetch || strtolower($return->expr->name->toString()) !== 'true') {
                return true;
            }
        }
        return false;
    }

    /**
     * Names of methods called on $this / self / static (helpers whose checks the caller inherits).
     *
     * @param Node[] $stmts
     * @return string[] lower-case method names
     */
    public function calledOwnMethods(array $stmts): array
    {
        $names = [];
        foreach ($this->finder->find($stmts, fn(Node $n) => $n instanceof Expr\MethodCall || $n instanceof Expr\StaticCall) as $call) {
            if (!$call->name instanceof Node\Identifier) {
                continue;
            }
            $own = $call instanceof Expr\MethodCall
                ? $call->var instanceof Expr\Variable && $call->var->name === 'this'
                : $call->class instanceof Node\Name && in_array(strtolower($call->class->toString()), ['self', 'static'], true);
            if ($own) {
                $names[] = strtolower($call->name->toString());
            }
        }
        return array_values(array_unique($names));
    }

    // -------------------------------------------------------------------------

    private function isUnauthenticatedSignal(Node $n): bool
    {
        if ($n instanceof Node\Scalar\Int_ && $n->value === 401) {
            return true;
        }
        if ($n instanceof Expr\ClassConstFetch && $n->name instanceof Node\Identifier
            && strtoupper($n->name->toString()) === 'HTTP_UNAUTHORIZED') {
            return true;
        }
        if ($n instanceof Expr\New_ && $n->class instanceof Node\Name
            && in_array(strtolower($n->class->getLast()), self::UNAUTHENTICATED_EXCEPTIONS, true)) {
            return true;
        }
        // Delegating to Laravel's Authenticate internals
        return $n instanceof Expr\MethodCall && $n->name instanceof Node\Identifier
            && in_array(strtolower($n->name->toString()), ['unauthenticated', 'authenticate'], true)
            && $n->var instanceof Expr\Variable && $n->var->name === 'this';
    }

    private function isForbiddenSignal(Node $n): bool
    {
        if ($n instanceof Node\Scalar\Int_ && $n->value === 403) {
            return true;
        }
        if ($n instanceof Expr\ClassConstFetch && $n->name instanceof Node\Identifier
            && strtoupper($n->name->toString()) === 'HTTP_FORBIDDEN') {
            return true;
        }
        return $n instanceof Expr\New_ && $n->class instanceof Node\Name
            && in_array(strtolower($n->class->getLast()), self::FORBIDDEN_EXCEPTIONS, true);
    }

    /**
     * @param Node[] $stmts
     */
    private function inspectsIdentity(array $stmts): bool
    {
        return $this->finder->findFirst($stmts, function (Node $n) {
            if (($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall) && $n->name instanceof Node\Identifier
                && in_array(strtolower($n->name->toString()), self::IDENTITY_CALLS, true)) {
                return true;
            }
            if ($n instanceof Expr\FuncCall && $n->name instanceof Node\Name
                && in_array(strtolower($n->name->getLast()), self::IDENTITY_FUNCTIONS, true)) {
                return true;
            }
            return $n instanceof Expr\StaticCall && $n->class instanceof Node\Name
                && in_array(strtolower($n->class->getLast()), self::IDENTITY_CLASSES, true);
        }) !== null;
    }

    /**
     * @param Node[] $stmts
     */
    private function readsCredential(array $stmts): bool
    {
        return $this->finder->findFirst($stmts, function (Node $n) {
            if (!($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall || $n instanceof Expr\StaticCall)
                || !$n->name instanceof Node\Identifier || $n->isFirstClassCallable()) {
                return false;
            }
            $name = strtolower($n->name->toString());
            $args = $n->getArgs();

            // $request->header('X-Partner'), $request->headers->get(...), $request->hasHeader(...)
            if (in_array($name, self::HEADER_ACCESSORS, true)) {
                return true;
            }
            if ($name === 'get' && $n instanceof Expr\MethodCall && $n->var instanceof Expr\PropertyFetch
                && $n->var->name instanceof Node\Identifier && strtolower($n->var->name->toString()) === 'headers') {
                return true;
            }
            // $request->input('api_key'), $request->query('token')
            if (in_array($name, self::REQUEST_ACCESSORS, true) && isset($args[0])
                && $args[0]->value instanceof Node\Scalar\String_
                && preg_match(self::CREDENTIAL_NAME, $args[0]->value->value) === 1) {
                return true;
            }
            // GatewayHandshake::isValid($request), $signer->verify($request), $otp->isValid($request->code)
            if (preg_match(self::VALIDATOR_NAME, $name) === 1) {
                foreach ($args as $arg) {
                    if ($this->derivesFromRequest($arg->value)) {
                        return true;
                    }
                }
            }
            return false;
        }) !== null;
    }

    /**
     * $request, $request->code, $request->input('code'), request('code').
     */
    private function derivesFromRequest(Expr $expr): bool
    {
        return $this->finder->findFirst([$expr], fn(Node $n) => ($n instanceof Expr\Variable && $n->name === 'request')
            || ($n instanceof Expr\FuncCall && $n->name instanceof Node\Name && strtolower($n->name->getLast()) === 'request')) !== null;
    }

    private function isClientErrorStatus(Node $node): bool
    {
        if ($node instanceof Node\Scalar\Int_) {
            return $node->value >= 400 && $node->value < 500;
        }
        return $node instanceof Expr\ClassConstFetch && $node->name instanceof Node\Identifier
            && in_array(strtoupper($node->name->toString()), ['HTTP_UNAUTHORIZED', 'HTTP_FORBIDDEN', 'HTTP_NOT_FOUND', 'HTTP_METHOD_NOT_ALLOWED', 'HTTP_GONE'], true);
    }

    private function isResponseFactoryCall(Expr\MethodCall $call): bool
    {
        $root = $call->var;
        while ($root instanceof Expr\MethodCall) {
            $root = $root->var;
        }
        return $root instanceof Expr\FuncCall && $root->name instanceof Node\Name
            && strtolower($root->name->getLast()) === 'response';
    }
}
