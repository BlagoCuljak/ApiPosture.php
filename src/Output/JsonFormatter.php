<?php

declare(strict_types=1);

namespace ApiPosture\Output;

use ApiPosture\Core\Model\ScanResult;

final class JsonFormatter implements OutputFormatterInterface
{
    public function format(ScanResult $result, array $options = []): string
    {
        $json = json_encode($result->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            return '{"error": "Failed to encode results as JSON"}';
        }

        return $json;
    }
}
