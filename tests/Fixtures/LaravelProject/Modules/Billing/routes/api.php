<?php

use Illuminate\Support\Facades\Route;
use Modules\Billing\Http\Controllers\InvoiceController;

Route::post('billing/invoices', [InvoiceController::class, 'store']);
