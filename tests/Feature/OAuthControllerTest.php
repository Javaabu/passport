<?php

namespace Javaabu\Passport\Tests\Feature;

use Javaabu\Passport\Tests\TestSupport\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Javaabu\Passport\Tests\TestSupport\Enums\UserStatuses;
use Javaabu\Passport\Tests\TestCase;
use Laravel\Passport\ClientRepository;

class OAuthControllerTest extends TestCase
{
    use RefreshDatabase;

    public function test_it_can_generate_a_client_credentials_access_token()
    {
        $user = $this->getUser();
        $client = (new ClientRepository())->createClientCredentialsGrantClient(
            'Test Client',
        );

        $this->json('post', '/oauth/token', [
            'client_id' => $client->id,
            'client_secret' => $client->plainSecret,
            'grant_type' => 'client_credentials',
            'scope' => '*',
        ])
            ->assertStatus(200)
            ->assertJsonStructure([
                'token_type',
                'expires_in',
                'access_token',
            ])
            ->assertJson([
                'token_type' => 'Bearer',
            ]);
    }

    public function test_it_can_generate_a_password_grant_access_token_for_an_admin()
    {
        $user = $this->getUser();
        $client = (new ClientRepository())->createPasswordGrantClient(
            'Test Client',
            'users',
        );

        $this->json('post', '/oauth/token', [
            'client_id' => $client->id,
            'client_secret' => $client->plainSecret,
            'grant_type' => 'password',
            'username' => $user->email,
            'password' => 'password',
            'scope' => '*',
        ])
            ->assertStatus(200)
            ->assertJsonStructure([
                'token_type',
                'expires_in',
                'access_token',
                'refresh_token',
            ])
            ->assertJson([
                'token_type' => 'Bearer',
            ]);
    }

    public function test_it_wont_grant_a_password_access_token_for_an_admin_with_incorrect_password()
    {
        $user = $this->getUser();
        $client = (new ClientRepository())->createPasswordGrantClient(
            'Test Client',
            'users'
        );

        $this->json('post', '/oauth/token', [
            'client_id' => $client->id,
            'client_secret' => $client->plainSecret,
            'grant_type' => 'password',
            'username' => $user->email,
            'password' => 'wrong password',
            'scope' => '*',
        ])
            ->assertStatus(400)
            ->assertJson([
                'error' => 'invalid_grant',
            ]);
    }

    public function test_it_can_authorize_an_admin()
    {
        $this->withoutExceptionHandling();

        $user = $this->getUser();
        $this->actingAsApiUser($user);

        $this->json('get', '/users/profile')
            ->assertStatus(200)
            ->assertJson([
                'name' => $user->name,
            ]);
    }

    public function test_it_wont_allow_an_inactive_admin()
    {
        $user = $this->getUser();
        $user->status = UserStatuses::PENDING;
        $user->save();

        $this->actingAsApiUser($user);

        $this->json('get', '/users/profile')
            ->assertStatus(403)
            ->assertJson([
                'message' => 'Account not activated',
            ]);

        $this->json('get', '/test')
            ->assertStatus(403)
            ->assertJson([
                'message' => 'Account not activated',
            ]);
    }

    public function test_it_can_authorize_a_client_access_token_from_auth_header()
    {
        $access_token = $this->getClientAccessToken();

        $this->json('get', '/test', [], [
            'Authorization' => "Bearer $access_token",
        ])
            ->assertStatus(200)
            ->assertJsonFragment([
                'It works',
            ]);
    }

    public function test_it_can_authorize_a_user_from_an_auth_token_cookie()
    {
        $user = $this->getUser();
        $access_cookie = $this->getOAuthCookie($user);

        // check if it doesn't work without an auth cookie
        $this->json('get', '/users/profile')
            ->assertStatus(401)
            ->assertDontSee($user->name);

        $this->jsonApi('get', '/users/profile', [], $access_cookie)
            ->assertStatus(200)
            ->assertJson([
                'name' => $user->name,
            ]);
    }

    public function test_it_can_authorize_client_credentials_from_an_auth_token_cookie()
    {
        $access_cookie = $this->getOAuthCookie(null);

        $this->jsonApi('get', '/test', [], $access_cookie)
            ->assertStatus(200)
            ->assertJsonFragment([
                'It works',
            ]);
    }

    public function test_it_generates_a_valid_token_cookie_for_inactive_users()
    {
        $user = $this->getUser();
        $user->status = UserStatuses::PENDING;
        $user->save();

        $this->actingAs($user, 'web');

        $access_cookie = $this->get('/verify')
            ->headers
            ->getCookies()[0];

        // check if it doesn't work without an auth cookie
        $this->json('get', '/test')
            ->assertStatus(401)
            ->assertDontSee('It works');

        // make sure can't access active routes
        $this->jsonApi('get', '/users/profile', [], $access_cookie->getValue())
            ->assertStatus(401)
            ->assertDontSee($user->name);

        $this->jsonApi('get', '/test', [], $access_cookie->getValue())
            ->assertStatus(200)
            ->assertJsonFragment([
                'It works',
            ]);
    }

    public function test_it_generates_a_valid_token_cookie_for_active_users()
    {
        $user = $this->getUser();

        $this->actingAs($user, 'web');

        $access_cookie = $this->get('/dashboard')
            ->assertStatus(200)
            ->headers
            ->getCookies()[0];

        // check if it doesn't work without an auth cookie
        $this->json('get', '/test')
            ->assertStatus(401)
            ->assertDontSee('It works');

        //make sure can't access active routes
        $this->jsonApi('get', '/users/profile', [], $access_cookie->getValue())
            ->assertStatus(200)
            ->assertJsonFragment([
                'name' => $user->name,
            ]);

        $this->jsonApi('get', '/test', [], $access_cookie->getValue())
            ->assertStatus(200)
            ->assertJsonFragment([
                'It works',
            ]);
    }
}
