<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class OpenRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }
}
