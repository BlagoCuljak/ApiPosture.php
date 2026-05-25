<?php

declare(strict_types=1);

namespace ApiPosture\Output;

use ApiPosture\Core\Model\Finding;
use ApiPosture\Core\Model\ScanResult;
use ApiPosture\Core\Model\Enums\Severity;

final class HtmlFormatter implements OutputFormatterInterface
{
    public function format(ScanResult $result, array $options = []): string
    {
        $lines = [];
        $lines[] = $this->htmlHead('ApiPosture Scan Results');
        $lines[] = '<body><div class="container">';
        $lines[] = '<h1>&#x1F6E1;&#xFE0F; ApiPosture Security Scan Report</h1>';
        $lines[] = '<div class="meta"><strong>Generated:</strong> ' . htmlspecialchars(date('Y-m-d H:i:s') . ' UTC') . '</div>';

        // Summary
        $lines[] = '<h2>Summary</h2>';
        $lines[] = '<div class="summary-grid">';
        $lines[] = $this->summaryCard('Scanned Path', $result->scannedPath);
        $lines[] = $this->summaryCard('Files Scanned', (string) count($result->scannedFiles));
        $lines[] = $this->summaryCard('Endpoints Found', (string) count($result->endpoints));
        $lines[] = $this->summaryCard('Findings', (string) count($result->findings));
        $lines[] = $this->summaryCard('Duration', sprintf('%.2fs', $result->duration));
        $lines[] = '</div>';

        // Severity breakdown
        if (!empty($result->findings)) {
            $lines[] = '<h2>Severity Breakdown</h2>';
            $lines[] = '<ul class="severity-list">';
            $counts = $this->countBySeverity($result->findings);
            foreach ($counts as $severityLabel => $count) {
                $sev = strtolower($severityLabel);
                $lines[] = '<li><span class="severity-badge severity-' . htmlspecialchars($sev) . '">'
                    . htmlspecialchars($severityLabel) . '</span> &mdash; ' . $count . ' finding(s)</li>';
            }
            $lines[] = '</ul>';
        }

        // Endpoints table
        if (!empty($result->endpoints)) {
            $lines[] = '<h2>Discovered Endpoints</h2>';
            $lines[] = '<table>';
            $lines[] = '  <thead><tr><th>Route</th><th>Methods</th><th>Classification</th><th>Controller</th><th>Auth</th></tr></thead>';
            $lines[] = '  <tbody>';
            foreach ($result->endpoints as $endpoint) {
                $methods  = $endpoint->methodsString();
                $classification = $endpoint->classification->label();
                $controller = $endpoint->controllerName ?? '-';
                $auth = $endpoint->authorization->hasAuth ? 'Yes' : 'No';
                $lines[] = '    <tr>'
                    . '<td><code>' . htmlspecialchars($endpoint->route) . '</code></td>'
                    . '<td>' . htmlspecialchars($methods) . '</td>'
                    . '<td>' . htmlspecialchars($classification) . '</td>'
                    . '<td>' . htmlspecialchars($controller) . '</td>'
                    . '<td>' . htmlspecialchars($auth) . '</td>'
                    . '</tr>';
            }
            $lines[] = '  </tbody>';
            $lines[] = '</table>';
        }

        // Findings detail
        if (!empty($result->findings)) {
            $lines[] = '<h2>Security Findings</h2>';
            foreach ($result->findings as $finding) {
                $lines[] = $this->renderFinding($finding);
            }
        } else {
            $lines[] = '<h2>Security Findings</h2>';
            $lines[] = '<div class="success">&#x2705; No security findings detected!</div>';
        }

        if (!empty($result->failedFiles)) {
            $lines[] = '<h2>Failed Files</h2><ul>';
            foreach ($result->failedFiles as $file) {
                $lines[] = '  <li><code>' . htmlspecialchars($file) . '</code></li>';
            }
            $lines[] = '</ul>';
        }

        $lines[] = '</div></body></html>';

        return implode("\n", $lines) . "\n";
    }

    private function renderFinding(Finding $finding): string
    {
        $sev = strtolower($finding->severity->name());
        $lines = [];
        $lines[] = '<div class="finding ' . htmlspecialchars($sev) . '">';
        $lines[] = '  <span class="severity-badge severity-' . htmlspecialchars($sev) . '">' . htmlspecialchars($finding->severity->label()) . '</span>';
        $lines[] = '  <h3>[' . htmlspecialchars($finding->ruleId) . '] ' . htmlspecialchars($finding->ruleName) . '</h3>';
        $lines[] = '  <p><strong>Route:</strong> <code>' . htmlspecialchars($finding->endpoint->route) . '</code></p>';
        $lines[] = '  <p><strong>Location:</strong> <code>' . htmlspecialchars((string) $finding->endpoint->location) . '</code></p>';
        $lines[] = '  <p>' . htmlspecialchars($finding->message) . '</p>';
        if (!empty($finding->recommendation)) {
            $lines[] = '  <div class="recommendation"><div class="recommendation-title">Recommendation</div>'
                . '<div>' . htmlspecialchars($finding->recommendation) . '</div></div>';
        }
        $lines[] = '</div>';
        return implode("\n", $lines);
    }

    private function summaryCard(string $label, string $value): string
    {
        return '<div class="summary-card"><div class="label">' . htmlspecialchars($label)
            . '</div><div class="value">' . htmlspecialchars($value) . '</div></div>';
    }

    /**
     * @param Finding[] $findings
     * @return array<string, int>
     */
    private function countBySeverity(array $findings): array
    {
        $counts = [];
        foreach (Severity::cases() as $severity) {
            $count = count(array_filter($findings, fn(Finding $f) => $f->severity === $severity));
            if ($count > 0) {
                $counts[$severity->label()] = $count;
            }
        }
        return $counts;
    }

    private function htmlHead(string $title): string
    {
        $css = '
        :root{--panel:#fff;--border:#dbe3ee;--text:#1e293b;--muted:#64748b;--critical:#dc2626;--high:#ea580c;--medium:#d97706;--low:#2563eb;--shadow:rgba(15,23,42,0.08);}
        *{box-sizing:border-box;}html{scroll-behavior:smooth;}
        body{margin:0;padding:32px;background:linear-gradient(to bottom right,#f8fafc,#eef4fb);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.6;}
        .container{max-width:1500px;margin:0 auto;}
        h1{font-size:42px;margin-bottom:8px;color:#0f172a;}h2{margin-top:50px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:12px;color:#0f172a;}h3{margin-top:0;color:#1e293b;}
        .meta{color:var(--muted);margin-bottom:40px;}
        .summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;margin-bottom:40px;}
        .summary-card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:24px;transition:0.2s ease;box-shadow:0 6px 20px var(--shadow);}
        .summary-card:hover{transform:translateY(-2px);}.summary-card .label{color:var(--muted);font-size:14px;}.summary-card .value{font-size:34px;font-weight:700;margin-top:8px;color:#0f172a;}
        table{width:100%;border-collapse:collapse;margin-top:18px;margin-bottom:30px;border-radius:14px;box-shadow:0 6px 18px var(--shadow);}
        th{background:#eff6ff;color:#1e293b;text-align:left;padding:15px;font-size:14px;border-bottom:1px solid var(--border);}
        td{background:var(--panel);border-top:1px solid var(--border);padding:15px;vertical-align:top;}tr:hover td{background:#f8fbff;}
        code{background:#eef2ff;color:#1d4ed8;padding:4px 8px;border-radius:6px;font-family:Consolas,monospace;font-size:13px;}
        .finding{background:var(--panel);border:1px solid var(--border);border-left:6px solid var(--medium);border-radius:16px;padding:24px;margin-bottom:24px;transition:0.2s ease;box-shadow:0 6px 18px var(--shadow);}
        .finding:hover{transform:translateY(-2px);}.finding.critical{border-left-color:var(--critical);}.finding.high{border-left-color:var(--high);}.finding.medium{border-left-color:var(--medium);}.finding.low{border-left-color:var(--low);}
        .severity-badge{display:inline-block;padding:5px 12px;border-radius:999px;font-size:12px;font-weight:bold;text-transform:uppercase;margin-bottom:14px;}
        .severity-critical{background:#fee2e2;color:#b91c1c;}.severity-high{background:#ffedd5;color:#c2410c;}.severity-medium{background:#fef3c7;color:#b45309;}.severity-low{background:#dbeafe;color:#1d4ed8;}.severity-info{background:#e5e7eb;color:#4b5563;}
        .recommendation{margin-top:20px;background:#f8fafc;border:1px solid var(--border);border-radius:12px;padding:18px;}.recommendation-title{color:#2563eb;font-weight:bold;margin-bottom:10px;}
        .severity-list{padding-left:18px;}.severity-list li{margin-bottom:8px;}
        .success{padding:18px;border-radius:12px;background:#dcfce7;color:#166534;border:1px solid #86efac;font-weight:bold;}
        .section-subtitle{color:var(--muted);margin-bottom:20px;}';

        return '<!DOCTYPE html>' . "\n"
            . '<html lang="en">' . "\n"
            . '<head>' . "\n"
            . '    <meta charset="UTF-8">' . "\n"
            . '    <meta name="viewport" content="width=device-width, initial-scale=1.0">' . "\n"
            . '    <title>' . htmlspecialchars($title) . '</title>' . "\n"
            . '    <style>' . $css . '</style>' . "\n"
            . '</head>';
    }
}
