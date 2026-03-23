<?php

namespace Javaabu\Passport\Tests\TestSupport\Enums;

enum UserStatuses: string
{
    case APPROVED = 'approved';
    case PENDING = 'pending';
    case BANNED = 'banned';
}
