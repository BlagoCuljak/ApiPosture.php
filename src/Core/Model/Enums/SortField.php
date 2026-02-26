<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model\Enums;

enum SortField: string
{
    case Severity = 'severity';
    case Route = 'route';
    case Method = 'method';
    case Classification = 'classification';
    case Controller = 'controller';
    case Location = 'location';
}
