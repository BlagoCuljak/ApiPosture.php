<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model\Enums;

enum HttpMethod: int
{
    case GET = 1;
    case POST = 2;
    case PUT = 4;
    case DELETE = 8;
    case PATCH = 16;

    public function label(): string
    {
        return $this->name;
    }

    public static function fromString(string $value): self
    {
        return match (strtoupper($value)) {
            'GET' => self::GET,
            'POST' => self::POST,
            'PUT' => self::PUT,
            'DELETE' => self::DELETE,
            'PATCH' => self::PATCH,
            default => throw new \InvalidArgumentException("Unknown HTTP method: {$value}"),
        };
    }

    public function isWriteMethod(): bool
    {
        return match ($this) {
            self::POST, self::PUT, self::DELETE, self::PATCH => true,
            default => false,
        };
    }

    /**
     * @param int $bitmask
     * @return self[]
     */
    public static function fromBitmask(int $bitmask): array
    {
        $methods = [];
        foreach (self::cases() as $case) {
            if ($bitmask & $case->value) {
                $methods[] = $case;
            }
        }
        return $methods;
    }

    /**
     * @param self[] $methods
     */
    public static function toBitmask(array $methods): int
    {
        $bitmask = 0;
        foreach ($methods as $method) {
            $bitmask |= $method->value;
        }
        return $bitmask;
    }
}
