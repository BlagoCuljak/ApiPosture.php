<?php

use Illuminate\Support\Facades\Route;

Route::post('/users', 'UserController@store');
Route::put('/users/{user}', ['as' => 'users.update', 'uses' => 'UserController@update']);
Route::get('/users', 'UserController@index');

Route::group(['namespace' => 'V1', 'prefix' => 'v1'], function () {
    Route::delete('/coupons/{id}', 'CouponController@destroy');
    Route::post('/coupons', 'CouponController@store');
});

Route::post('/appointments/cancel', 'AppointmentController@cancel');
Route::post('/appointments/no-show', 'AppointmentController@noShow');

Route::post('/partner/orders', 'PartnerController@store')->middleware('partner');
Route::post('/sync', ['middleware' => 'signed.key', 'uses' => 'PartnerController@sync']);
Route::post('/trial/extend', 'PartnerController@extend')->middleware('trial');
Route::post('/newsletter', 'PartnerController@subscribe')->middleware('validate.email');
Route::delete('/staff/users/{id}', 'UserController@destroy')->middleware('staff');

Route::post('/appointments/refund', 'PartnerController@extend')->middleware('invoiced');
Route::post('/signup/otp', 'PartnerController@subscribe')->middleware('otp');
Route::post('/validate/email', 'PartnerController@sync')->middleware('gateway.or.staff');

Route::post('/profile/update', 'SignupController@updateProfile');
Route::post('/profile/open', 'SignupController@open');
Route::post('/profile/staff', 'SignupController@staff');
Route::post('/signup', 'SignupController@store');
Route::post('/signup/draft', 'SignupController@draft');

// Retired URLs reserved so they cannot fall through to other routes.
Route::delete('/cache', function () {
    abort(403, 'Cache maintenance is only available through Artisan.');
});
Route::post('/legacy/export', fn () => response()->json(['error' => 'Gone'], 410));
Route::post('/legacy/import', function () {
    if (!hash_equals((string) config('services.import_key'), (string) request()->header('X-Import-Key'))) {
        abort(401);
    }
    return 'ok';
});
Route::post('/legacy/echo', function () {
    return request()->all();
});
