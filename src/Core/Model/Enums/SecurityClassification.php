<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model\Enums;

enum SecurityClassification: string
{
    case Public = 'public';
    case Authenticated = 'authenticated';
    case RoleRestricted = 'role_restricted';
    case PolicyRestricted = 'policy_restricted';

    public function label(): string
    {
        return match ($this) {
            self::Public => 'Public',
            self::Authenticated => 'Authenticated',
            self::RoleRestricted => 'Role Restricted',
            self::PolicyRestricted => 'Policy Restricted',
        };
    }
}
