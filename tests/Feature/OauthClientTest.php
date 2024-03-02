<?php

namespace Javaabu\Passport\Tests\Feature;

use Javaabu\Passport\Tests\TestCase;
use Laravel\Passport\ClientRepository;

class OauthClientTest extends TestCase
{

    /** @test */
    public function it_can_generate_a_client_credentials_access_token()
    {
        $this->withoutExceptionHandling();

        $user = $this->getUser();

        $client = (new ClientRepository())->create(
            $user->id,
            'Test Client',
            'http://localhost.test'
        );

        $this->json('post', '/oauth/token', [
            'client_id'     => $client->id,
            'client_secret' => $client->secret,
            'grant_type'    => 'client_credentials',
            'scope'         => '*',
        ])
            ->assertStatus(200)
            ->assertJsonStructure([
                'token_type',
                'expires_in',
                'access_token',
            ])
            ->assertJson([
                'token_type' => 'Bearer'
            ]);
    }

    /** @test */
    public function it_can_generate_a_password_grant_access_token_for_an_admin()
    {
        $user = $this->getUser();
        $client = (new ClientRepository())->create(
            $user->id,
            'Test Client',
            'http://localhost.test',
            'users',
            false,
            true
        );

        $this->json('post', '/oauth/token', [
            'client_id'     => $client->id,
            'client_secret' => $client->secret,
            'grant_type'    => 'password',
            'username'      => $user->email,
            'password'      => 'password',
            'scope'         => '*',
        ])
            ->assertStatus(200)
            ->assertJsonStructure([
                'token_type',
                'expires_in',
                'access_token',
                'refresh_token',
            ])
            ->assertJson([
                'token_type' => 'Bearer'
            ]);
    }

    /** @test */
    public function it_wont_grant_a_password_access_token_for_an_admin_with_incorrect_password()
    {
        $user = $this->getUser();
        $client = (new ClientRepository())->create(
            $user->id,
            'Test Client',
            'http://localhost.test',
            'users',
            false,
            true
        );

        $this->json('post', '/oauth/token', [
            'client_id'     => $client->id,
            'client_secret' => $client->secret,
            'grant_type'    => 'password',
            'username'      => $user->email,
            'password'      => 'wrong password',
            'scope'         => '*',
        ])
            ->assertStatus(400)
            ->assertJson([
                'error' => 'invalid_grant'
            ]);
    }

    /** @test */
    public function it_can_authorize_a_client_access_token_from_auth_header()
    {
        $access_token = $this->getClientAccessToken();

        $this->json('get', '/test', [], [
            'Authorization' => "Bearer $access_token",
        ])
            ->assertStatus(200)
            ->assertJsonFragment([
                'It works'
            ]);
    }
}
