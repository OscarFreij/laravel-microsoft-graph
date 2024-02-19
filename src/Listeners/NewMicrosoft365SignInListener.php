<?php

namespace App\Listeners;

use App\Models\User;
use Dcblogdev\MsGraph\MsGraph;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\JwtController;

class NewMicrosoft365SignInListener
{
    public function handle($event)
    {
        #dd($event);
        $user  = User::firstOrCreate([
            'email' => $event->token['info']['mail'],
        ], [
            'name'     => $event->token['info']['displayName'],
            'email'    => $event->token['info']['mail'] ?? $event->token['info']['userPrincipalName'],
            'source'   => 'ms_entra_id',
            'password' => '',
        ]);

        
        // Update role if user->source is ms_entra_id
        if ($user->source == 'ms_entra_id')
        {
            $user->assignRole(JwtController::decode($event->token['idToken'])->roles[0]);
            $user->save();
        }

        

        (new MsGraph())->storeToken(
            $event->token['idToken'],
            $event->token['accessToken'],
            $event->token['refreshToken'],
            $event->token['expires'],
            $user->id,
            $user->email
        );

        Auth::login($user);
    }
}