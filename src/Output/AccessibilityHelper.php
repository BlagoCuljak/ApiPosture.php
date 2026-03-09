<?php

declare(strict_types=1);

namespace ApiPosture\Output;

use ApiPosture\Core\Model\Enums\SecurityClassification;
use ApiPosture\Core\Model\Enums\Severity;

/**
 * Provides accessibility options for terminal output including color-free
 * and icon-free alternatives. Mirrors the .NET reference implementation's
 * auto-detection of NO_COLOR, TTY redirect, and Windows legacy consoles.
 */
final class AccessibilityHelper
{
    private readonly bool $useColors;
    private readonly bool $useIcons;

    // Severity emoji icons
    private const SEVERITY_ICONS = [
        Severity::Critical->value => "\u{274C}",      // Red X
        Severity::High->value     => "\u{26A0}\u{FE0F}", // Warning sign
        Severity::Medium->value   => "\u{26A1}",       // Lightning bolt
        Severity::Low->value      => "\u{2139}\u{FE0F}", // Info
        Severity::Info->value     => "\u{2139}\u{FE0F}", // Info
    ];

    // Severity text fallbacks matching .NET reference
    private const SEVERITY_LABELS = [
        Severity::Critical->value => '[CRIT]',
        Severity::High->value     => '[HIGH]',
        Severity::Medium->value   => '[MED]',
        Severity::Low->value      => '[LOW]',
        Severity::Info->value     => '[INFO]',
    ];

    // Classification emoji icons
    private const CLASSIFICATION_ICONS = [
        SecurityClassification::Public->value          => "\u{1F513}", // Unlocked
        SecurityClassification::Authenticated->value   => "\u{1F510}", // Lock with key
        SecurityClassification::RoleRestricted->value  => "\u{1F512}", // Locked
        SecurityClassification::PolicyRestricted->value => "\u{1F6E1}", // Shield
    ];

    // Classification text fallbacks matching .NET reference
    private const CLASSIFICATION_LABELS = [
        SecurityClassification::Public->value          => '[PUBLIC]',
        SecurityClassification::Authenticated->value   => '[AUTH]',
        SecurityClassification::RoleRestricted->value  => '[ROLE]',
        SecurityClassification::PolicyRestricted->value => '[POLICY]',
    ];

    public function __construct(bool $useColors = true, bool $useIcons = true)
    {
        $this->useColors = $useColors;
        $this->useIcons  = $useIcons;
    }

    /**
     * Creates an AccessibilityHelper from CLI flags, applying environment-based
     * auto-detection when the flags have not already forced a value.
     */
    public static function create(bool $noColorFlag = false, bool $noIconsFlag = false): self
    {
        $useColors = self::determineUseColors($noColorFlag);
        $useIcons  = self::determineUseIcons($noIconsFlag);
        return new self($useColors, $useIcons);
    }

    private static function determineUseColors(bool $noColorFlag): bool
    {
        if ($noColorFlag) {
            return false;
        }
        // NO_COLOR environment variable (https://no-color.org/)
        $noColor = getenv('NO_COLOR');
        if ($noColor !== false && $noColor !== '') {
            return false;
        }
        // Disable colors when stdout is not a TTY (redirected output)
        if (defined('STDOUT') && function_exists('stream_isatty') && !stream_isatty(STDOUT)) {
            return false;
        }
        return true;
    }

    private static function determineUseIcons(bool $noIconsFlag): bool
    {
        if ($noIconsFlag) {
            return false;
        }
        // Auto-detect: disable icons on Windows legacy consoles (cmd.exe, PowerShell)
        // which cannot render emoji. Windows Terminal sets WT_SESSION and handles emoji fine.
        if (PHP_OS_FAMILY === 'Windows') {
            $wtSession = getenv('WT_SESSION');
            if ($wtSession === false || $wtSession === '') {
                return false;
            }
        }
        return true;
    }

    public function useColors(): bool { return $this->useColors; }
    public function useIcons(): bool  { return $this->useIcons; }

    public function getSeverityIndicator(Severity $severity): string
    {
        if ($this->useIcons) {
            return self::SEVERITY_ICONS[$severity->value] ?? '?';
        }
        return self::SEVERITY_LABELS[$severity->value] ?? '[?]';
    }

    public function getClassificationIndicator(SecurityClassification $classification): string
    {
        if ($this->useIcons) {
            return self::CLASSIFICATION_ICONS[$classification->value] ?? '?';
        }
        return self::CLASSIFICATION_LABELS[$classification->value] ?? '[?]';
    }

    public function getSuccessIndicator(): string  { return $this->useIcons ? "\u{2705}" : '[OK]'; }
    public function getFailureIndicator(): string  { return $this->useIcons ? "\u{274C}"  : '[FAIL]'; }
    public function getWarningIndicator(): string  { return $this->useIcons ? "\u{26A0}\u{FE0F}" : '[WARN]'; }
}
