<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model;

final class SourceLocation
{
    public function __construct(
        public readonly string $filePath,
        public readonly int $lineNumber,
        public readonly int $columnNumber = 0,
    ) {}

    public function __toString(): string
    {
        return "{$this->filePath}:{$this->lineNumber}";
    }

    public function toArray(): array
    {
        return [
            'filePath' => $this->filePath,
            'lineNumber' => $this->lineNumber,
            'columnNumber' => $this->columnNumber,
        ];
    }
}
