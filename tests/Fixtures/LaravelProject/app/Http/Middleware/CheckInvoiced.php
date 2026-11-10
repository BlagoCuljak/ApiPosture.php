<?php

namespace App\Http\Middleware;

use App\Appointment;
use Closure;
use Illuminate\Http\JsonResponse;

// Returns 401 from a business rule (the appointment is invoiced) without looking at the caller: not authentication.
class CheckInvoiced
{
    public function handle($request, Closure $next)
    {
        $appointment = Appointment::whereUuid($request->appointment_uuid)->firstOrFail();

        if ($appointment->invoice) {
            return new JsonResponse(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
