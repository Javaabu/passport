<?php

namespace Javaabu\Passport\Tests\Feature\Http\Controllers\Api;

use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Schema;
use Spatie\QueryBuilder\QueryBuilderRequest;

class UsersController extends ApiController
{
    /**
     * Instantiate a new controller instance.
     *
     * @param QueryBuilderRequest $request
     */
    public function __construct(QueryBuilderRequest $request)
    {
        parent::__construct($request);

        $this->middleware('auth.guest')->only('store');
        //$this->middleware('can:access_admin')->only('index');
    }

    /**
     * Logout
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function revoke(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json(true);
    }

    /**
     * Display current user
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function profile(Request $request)
    {
        return $this->show($request->user()->id, $request);
    }

    /**
     * Check if allowed to view
     *
     * @param Model $model
     */
    protected function authorizeView(Model $model): void
    {
        $this->authorize('view', $model);
    }

    protected function getBaseQuery(): Builder
    {
        return User::query();
    }

    protected function getAllowedFields(): array
    {
        return array_diff(Schema::getColumnListing('users'), (new User())->getHidden());
    }

    /**
     * Get the index allowed fields
     */
    protected function getIndexAllowedFields(): array
    {
        return [
            'id',
            'name'
        ];
    }

    protected function getAllowedIncludes(): array
    {
        return [];
    }

    protected function getAllowedAppends(): array
    {
        return [
        ];
    }

    protected function getAllowedSorts(): array
    {
        return [
            'id',
            'name',
            'created_at',
            'updated_at',
        ];
    }

    protected function getDefaultSort(): string
    {
        return '-created_at';
    }

    protected function getAllowedFilters(): array
    {
        return [
            'name',
        ];
    }
}
