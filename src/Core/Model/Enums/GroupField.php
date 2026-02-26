<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model\Enums;

enum GroupField: string
{
    case Controller = 'controller';
    case Classification = 'classification';
    case Severity = 'severity';
    case Method = 'method';
    case Type = 'type';
}
