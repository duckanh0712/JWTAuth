<?php
namespace App\Http\Controllers;
use App\Mail\MailNotify;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use App\User;
use Mail;
class UserController extends Controller
{
    public function register(Request $request)
    {
        $params = $request->only('email', 'name', 'password');
        $user = new User();
        $user->email = $params['email'];
        $user->name = $params['name'];
        $user->password = bcrypt($params['password']);
        $user->save();
        if ($user) {
            Mail::to($user)->send(new MailNotify($user->name));}

        return response()->json($user, Response::HTTP_OK);
    }

    public function login(Request $request)
    {


        $credentials = $request->only('email', 'password');
        Redis::connection();
        Redis::set('email',$request->email);
        Redis::set('password',$request->password);
        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 401);
            }
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }
        $refresh_token = bcrypt(rand(0,9));
        DB::table('users')->where('email',$request->email)->update(array(
            'refresh_token'=>$refresh_token));
        return response()->json([
            'message' => 'Login successful',
            'access_token' => $token,
            'refresh_token' => $refresh_token
        ]);
    }

    public function user(Request $request)
    {

        $user = Auth::user();
        if ($user) {
            return response($user, Response::HTTP_OK);
        }
        return response(null, Response::HTTP_BAD_REQUEST);
    }

    /**
     * Log out
     * Invalidate the token, so user cannot use it anymore
     * They have to relogin to get a new token
     *
     * @param Request $request
     */
    public function logout(Request $request) {
        $this->validate($request, ['token' => 'required']);

        try {
            JWTAuth::invalidate($request->input('token'));
            DB::table('users')->where('email',$request->email)->update(array('refresh_token'=>NULL));
            return response()->json('You have successfully logged out.', Response::HTTP_OK);
        } catch (JWTException $e) {
            return response()->json('Failed to logout, please try again.', Response::HTTP_BAD_REQUEST);
        }
    }

    public function refresh(Request $request)
    {
            Redis::connection();
            $credentials = ['email' =>Redis::get('email'), 'password' => Redis::get('password') ];
            $refresh_token = $request->refresh_token;
            $refresh_tokenDB  = DB::table('users')->where('refresh_token',$refresh_token)->first();
            if (!empty($refresh_tokenDB)) {
                $token = JWTAuth::attempt($credentials);
                return response()->json(['token' => $token, 'refresh_token' => $refresh_token], Response::HTTP_OK);

            }
            else {
                return response()->json(['error' => 'invalid_refresh_token'], 401);
            }
    }
}
