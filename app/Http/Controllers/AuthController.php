<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Validator;
use App\Models\User;
use App\Http\Traits\ResponseTrait;

class AuthController extends Controller
{ 
    use ResponseTrait; 

    /**
     * Create a new AuthController instance.
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    /**
     * Sign up.
     */
    public function register(Request $request) {
        $req = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if($req->fails()){
            return $this->error(400, ['errors' => $req->errors()], 'bad_input');
        }

        $user = User::create(array_merge(
                    $req->validated(),
                    ['password' => bcrypt($request->password)]
                ));

        return $this->success(201, ['user' => $user], 'User account created successfully.');
    }

    /**
     * Get a JWT token via given credentials.
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if ($token = $this->guard()->attempt($credentials)) {
            return $this->respondWithToken($token);
        }

        return $this->error(401, [], 'unauthorized');
    }

    /**
     * Get the authenticated User
     */
    public function mine()
    {
        return $this->success(200, ['user' => $this->guard()->user()]);
    }

    /**
     * Log the user out (Invalidate the token)
     */
    public function logout()
    {
        $this->guard()->logout();

        return $this->success(200, null, 'Successfully logged out');
    }

    /**
     * Refresh a token.
     */
    public function refresh()
    {
        return $this->respondWithToken($this->guard()->refresh());
    }

    /**
     * Get the token array structure.
     */
    protected function respondWithToken($token)
    {
        $data = [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->guard()->factory()->getTTL() * 60
        ];

        return $this->success(200, $data);
    }

    /**
     * Get the guard to be used during authentication.
     */
    public function guard()
    {
        return auth('api');
    }

}
