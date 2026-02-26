<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware('role:admin|editor')->only(['destroy']);
    }

    public function index()
    {
        return response()->json(User::all());
    }

    public function store()
    {
        // Create user
    }

    public function update($id)
    {
        // Update user
    }

    public function destroy($id)
    {
        // Delete user
    }
}
