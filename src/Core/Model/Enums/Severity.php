<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model\Enums;

enum Severity: int
{
    case Info = 0;
    case Low = 1;
    case Medium = 2;
    case High = 3;
    case Critical = 4;

    public function label(): string
    {
        return match ($this) {
            self::Info => 'Info',
            self::Low => 'Low',
            self::Medium => 'Medium',
            self::High => 'High',
            self::Critical => 'Critical',
        };
    }

    public static function fromString(string $value): self
    {
        return match (strtolower($value)) {
            'info' => self::Info,
            'low' => self::Low,
            'medium' => self::Medium,
            'high' => self::High,
            'critical' => self::Critical,
            default => throw new \InvalidArgumentException("Unknown severity: {$value}"),
        };
    }
}
