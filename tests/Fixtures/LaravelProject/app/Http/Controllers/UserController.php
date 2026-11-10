<?php

namespace App\Http\Controllers;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth', ['only' => ['store', 'update']]);
    }

    public function index() {}
    public function store() {}
    public function update() {}
    public function destroy() {}
}
