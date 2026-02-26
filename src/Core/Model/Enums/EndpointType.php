<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model\Enums;

enum EndpointType: string
{
    case Controller = 'controller';
    case Route = 'route';
    case Annotation = 'annotation';
}
