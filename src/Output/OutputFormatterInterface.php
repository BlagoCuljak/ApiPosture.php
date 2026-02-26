<?php

declare(strict_types=1);

namespace ApiPosture\Output;

use ApiPosture\Core\Model\ScanResult;

interface OutputFormatterInterface
{
    public function format(ScanResult $result, array $options = []): string;
}
