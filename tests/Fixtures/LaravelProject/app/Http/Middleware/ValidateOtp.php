<?php

namespace App\Http\Middleware;

use App\SmsVerification;
use Closure;

// Verifies a one-time code the caller must possess: authentication.
class ValidateOtp
{
    public function handle($request, Closure $next)
    {
        $verification = SmsVerification::find($request->telephone);
        if (!$verification->isValid($request->code)) {
            return response()->json(['error' => 'SMS verification failed'], 401);
        }

        return $next($request);
    }
}
