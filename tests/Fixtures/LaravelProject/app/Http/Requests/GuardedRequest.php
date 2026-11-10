<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

abstract class GuardedRequest extends FormRequest
{
    public function authorize(): bool
    {
        return (bool) $this->user()?->is_staff;
    }
}
