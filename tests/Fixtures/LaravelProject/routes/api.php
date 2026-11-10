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
