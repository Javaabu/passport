<?php

namespace Javaabu\Passport\Traits;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Laravel\Passport\PassportUserProvider;

trait HasUserIdentifier
{
    /**
     * Get the user id parts
     * @param $identifier
     * @return array
     */
    public function explodeUserIdentifier($identifier)
    {
        $params = explode('_', $identifier, 2); // https://stackoverflow.com/questions/3507901/how-can-i-split-a-string-at-the-first-occurrence-of-minus-sign-into-two-v

        return [
            'user_id' => isset($params[0]) ? $params[0] : null,
            'user_type' => isset($params[1]) ? $params[1] : null,
        ];
    }

    /**
     * Get the user provider
     * @param $identifier
     */
    public function getUserType($identifier)
    {
        return $this->explodeUserIdentifier($identifier)['user_type'];
    }

    /**
     * Get the user id
     * @param $identifier
     */
    public function getUserId($identifier)
    {
        return $this->explodeUserIdentifier($identifier)['user_id'];
    }

    /**
     * Create a user identifier
     * @param $id
     * @param $user_type
     * @return string
     */
    public function makeUserIdentifier($id, $user_type)
    {
        return $id.'_'.$user_type;
    }

    public function getPassportUserProvider($user_type): ?PassportUserProvider
    {
        // fix for when not using morph map
        if (class_exists($user_type)) {
            $user_type = Str::lower(class_basename($user_type));
        }

        $provider = Str::plural($user_type);

        // check if provider exists
        $providers = Arr::wrap(config('auth.providers', []));

        if (array_key_exists($provider, $providers)) {
            return new PassportUserProvider(Auth::createUserProvider($provider), $provider);
        }

        return null;
    }

    /**
     * Retrieve the user by id
     * @param $identifier
     * @return null
     */
    protected function retrieveUserById($identifier)
    {
        $user_params = $this->explodeUserIdentifier($identifier);

        $user_id = isset($user_params['user_id']) ? $user_params['user_id'] : '';
        $user_type = isset($user_params['user_type']) ? $user_params['user_type'] : '';

        if ($provider = $this->getPassportUserProvider($user_type)) {
            return $provider->retrieveById($user_id);
        }

        return null;
    }
}
