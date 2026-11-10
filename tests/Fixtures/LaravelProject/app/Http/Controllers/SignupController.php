<?php

namespace App\Http\Controllers;

use App\Http\Requests\OpenRequest;
use App\Http\Requests\StaffOnlyRequest;
use App\Http\Requests\UpdateProfileRequest;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;

class SignupController extends Controller
{
    public function updateProfile(UpdateProfileRequest $request) {}

    public function open(OpenRequest $request) {}

    public function staff(StaffOnlyRequest $request) {}

    // Enforcement lives in a private helper.
    public function store(Request $request)
    {
        $this->authorizeSignup($request);
    }

    // Helper that only validates input: no enforcement inherited.
    public function draft(Request $request)
    {
        $this->normalize($request);
    }

    private function authorizeSignup(Request $request): void
    {
        $jwt = (string) $request->header('X-Login-JWT');
        abort_if($jwt === '', 401);
        $claims = JWT::decode($jwt, new Key(config('auth.jwt_key'), 'HS256'));
        abort_if($claims->email !== $request->input('email'), 403);
    }

    private function normalize(Request $request): void
    {
        abort_if($request->input('owner_uuid') !== $request->input('user_uuid'), 403);
    }
}
