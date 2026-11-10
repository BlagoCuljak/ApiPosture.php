<?php

namespace App\Http\Requests;

class UpdateProfileRequest extends BaseRequest
{
    public function authorize(): bool
    {
        return auth('api')->check();
    }

    public function rules(): array
    {
        return ['name' => 'required|string'];
    }
}
