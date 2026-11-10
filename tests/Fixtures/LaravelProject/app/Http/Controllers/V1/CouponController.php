<?php

namespace App\Http\Controllers\V1;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Gate;

class CouponController extends Controller
{
    public function destroy($id)
    {
        Gate::authorize('manage-coupons');
    }

    public function store() {}
}
