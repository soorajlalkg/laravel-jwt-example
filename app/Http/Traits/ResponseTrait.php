<?php

namespace App\Http\Traits;

trait ResponseTrait {

    /**
     * Return a success JSON response.
     */
	protected function success(int $code = 200, $data, string $message = null)
	{
		return response()->json([
			'status' => true,
			'message' => $message,
			'data' => $data
		], $code);
	}

	/**
     * Return an error JSON response.
     */
	protected function error(int $code, $data = null, string $message = null)
	{
		return response()->json([
			'status' => false,
			'error' => $message,
			'details' => $data
		], $code);
	}

}