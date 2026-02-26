<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model\Enums;

enum SortDirection: string
{
    case Ascending = 'asc';
    case Descending = 'desc';
}
