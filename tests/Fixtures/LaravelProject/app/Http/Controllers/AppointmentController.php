<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Validation\UnauthorizedException;

class AppointmentController extends Controller
{
    // Checks the authenticated user: real enforcement.
    public function cancel(Request $request)
    {
        if ($request->user() === null) {
            throw new UnauthorizedException();
        }
    }

    // Compares two values the caller supplies: not authentication.
    public function noShow(Request $request)
    {
        if ($request->get('owner_uuid') !== $request->get('user_uuid')) {
            throw new UnauthorizedException();
        }
    }
}
