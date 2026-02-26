<?php

declare(strict_types=1);

namespace ApiPosture\Core\Model;

final class ScanResult
{
    /**
     * @param Endpoint[] $endpoints
     * @param Finding[] $findings
     * @param string[] $scannedFiles
     * @param string[] $failedFiles
     */
    public function __construct(
        public readonly string $scannedPath,
        public readonly array $endpoints,
        public readonly array $findings,
        public readonly array $scannedFiles = [],
        public readonly array $failedFiles = [],
        public readonly float $duration = 0.0,
    ) {}

    public function toArray(): array
    {
        return [
            'scannedPath' => $this->scannedPath,
            'endpoints' => array_map(fn(Endpoint $e) => $e->toArray(), $this->endpoints),
            'findings' => array_map(fn(Finding $f) => $f->toArray(), $this->findings),
            'scannedFiles' => $this->scannedFiles,
            'failedFiles' => $this->failedFiles,
            'duration' => $this->duration,
            'summary' => [
                'totalEndpoints' => count($this->endpoints),
                'totalFindings' => count($this->findings),
                'totalFilesScanned' => count($this->scannedFiles),
                'totalFilesFailed' => count($this->failedFiles),
            ],
        ];
    }
}
