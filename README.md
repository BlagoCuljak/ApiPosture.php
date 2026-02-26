# ApiPosture.php

[![Build and Test](https://github.com/BlagoCuljak/ApiPosture.php/actions/workflows/build.yml/badge.svg)](https://github.com/BlagoCuljak/ApiPosture.php/actions/workflows/build.yml)
[![Packagist Version](https://img.shields.io/packagist/v/apiposture/apiposture?logo=packagist&label=Packagist)](https://packagist.org/packages/apiposture/apiposture)
[![Packagist Downloads](https://img.shields.io/packagist/dt/apiposture/apiposture?logo=packagist&label=Downloads)](https://packagist.org/packages/apiposture/apiposture)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP](https://img.shields.io/badge/PHP-8.1%20|%208.2%20|%208.3%20|%208.4-777BB4?logo=php)](https://www.php.net/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://checkout.revolut.com/pay/525834c6-21cd-4d72-bb99-2dc27d3a0a6d)

A CLI security inspection tool for PHP APIs. Performs static source-code analysis using [nikic/php-parser](https://github.com/nikic/PHP-Parser) to identify authorization misconfigurations and security risks in Laravel, Symfony, and Slim applications.

## Features

- Static analysis of PHP projects (no runtime required)
- Discovers endpoints from Laravel routes, Symfony attributes, and Slim route definitions
- Detects 8 common security issues with authorization
- Multiple output formats: Terminal, JSON, Markdown
- Sorting, filtering, and grouping of results
- Configuration file support with suppressions
- Accessibility options (no-color, no-icons)
- CI/CD integration with `--fail-on` exit codes
- Works with PHP 8.1+

## Installation

```bash
# Install as a project dependency
composer require --dev apiposture/apiposture

# Or install globally
composer global require apiposture/apiposture
```

## Usage

```bash
# Scan a project directory
vendor/bin/apiposture scan ./app

# Scan specific directory
vendor/bin/apiposture scan ./src/Controller

# Output as JSON
vendor/bin/apiposture scan . --output json

# Output as Markdown report
vendor/bin/apiposture scan . --output markdown --output-file report.md

# Filter by severity
vendor/bin/apiposture scan . --severity medium

# CI integration - fail if high severity findings
vendor/bin/apiposture scan . --fail-on high

# Sorting
vendor/bin/apiposture scan . --sort-by route --sort-dir asc

# Filtering
vendor/bin/apiposture scan . --classification public --method POST
vendor/bin/apiposture scan . --route-contains admin --controller UserController

# Grouping
vendor/bin/apiposture scan . --group-by controller
vendor/bin/apiposture scan . --group-findings-by severity

# Accessibility (no colors/icons)
vendor/bin/apiposture scan . --no-color --no-icons

# Use config file
vendor/bin/apiposture scan . --config .apiposture.json
```

## Supported Frameworks

### Laravel
- `Route::get()`, `Route::post()`, `Route::put()`, `Route::delete()`, `Route::patch()`
- `Route::middleware(['auth'])->group(...)` with nested routes
- `Route::prefix('/api')->group(...)` with path prefixes
- Controller middleware via `$this->middleware('auth')` in constructors
- `#[Middleware('auth')]` attributes (Laravel 11+)
- Auth detection: `auth`, `auth:sanctum`, `auth:api`, `role:*`, `can:*`, `guest`

### Symfony
- `#[Route('/path', methods: ['GET'])]` attributes
- `#[IsGranted('ROLE_ADMIN')]` security attributes
- `#[Security("is_granted('ROLE_USER')")]` expressions
- Class-level route prefixes and security inheritance
- `ROLE_*` pattern detection

### Slim
- `$app->get()`, `$app->post()`, `$app->put()`, `$app->delete()`, `$app->patch()`
- `$app->group('/prefix', ...)` with nested routes
- `->add(new AuthMiddleware())` middleware chains
- Auth middleware detection via naming conventions

## Configuration File

Create `.apiposture.json` in your project root:

```json
{
  "severity": { "default": "low", "failOn": "high" },
  "suppressions": [
    { "route": "/api/health", "ruleId": "AP001" },
    { "route": "/api/webhook/*", "ruleId": "AP002" }
  ],
  "rules": {
    "AP006": { "enabled": false }
  },
  "display": { "useColors": true, "useIcons": true }
}
```

## Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| AP001 | Public without explicit intent | Medium | Endpoint is publicly accessible without `guest` middleware or explicit marker |
| AP002 | AllowAnonymous on write | High* | Public POST/PUT/DELETE/PATCH operations |
| AP003 | Controller/action conflict | High | Action overrides controller-level auth with anonymous access |
| AP004 | Missing auth on writes | Critical | Write endpoint with zero authentication whatsoever |
| AP005 | Excessive role access | Medium | More than 3 roles on a single endpoint |
| AP006 | Weak role naming | Low | Generic role names like "user", "admin", "guest" |
| AP007 | Sensitive route keywords | High/Low | `admin`, `debug`, `export`, `secret` in routes (High without auth, Low with auth) |
| AP008 | Unprotected endpoint | High/Info | Endpoint with no auth middleware (High for writes, Info for reads) |

*AP002 severity adjusts dynamically: webhooks → Medium, auth/login endpoints → Low, analytics → Low

## Example Output

### Sample Terminal Output
```
ApiPosture Scan Results
────────────────────────────────────────────────────────
  Path:     /path/to/project
  Duration: 0.25s
  Files:    15 scanned

Summary
+-------------+-------+
| Metric      | Count |
+-------------+-------+
| Endpoints   | 42    |
| Findings    | 8     |
|   Critical  | 1     |
|   High      | 3     |
|   Medium    | 2     |
|   Low       | 2     |
+-------------+-------+

Endpoints
+---------------------+---------+----------------+----------------+------+
| Route               | Methods | Classification | Controller     | Auth |
+---------------------+---------+----------------+----------------+------+
| /api/users          | GET     | Authenticated  | UserController | Yes  |
| /api/admin          | GET     | Public         | AdminController| No   |
| /api/orders         | POST    | Role Restricted| OrderController| Yes  |
+---------------------+---------+----------------+----------------+------+
```

## GitHub Actions Integration

Create `.github/workflows/api-security-scan.yml`:

### Basic Workflow

```yaml
name: API Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup PHP
      uses: shivammathur/setup-php@v2
      with:
        php-version: '8.3'

    - name: Install dependencies
      run: composer install --prefer-dist --no-progress

    - name: Scan API for security issues
      run: vendor/bin/apiposture scan ./app --fail-on high
```

### Advanced Workflow with Reports

```yaml
name: API Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup PHP
      uses: shivammathur/setup-php@v2
      with:
        php-version: '8.3'

    - name: Install dependencies
      run: composer install --prefer-dist --no-progress

    - name: Run security scan
      id: scan
      continue-on-error: true
      run: |
        vendor/bin/apiposture scan ./app \
          --output json \
          --output-file scan-results.json \
          --fail-on high

    - name: Generate Markdown report
      if: always()
      run: |
        vendor/bin/apiposture scan ./app \
          --output markdown \
          --output-file api-security-report.md

    - name: Upload JSON results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: security-scan-json
        path: scan-results.json

    - name: Upload Markdown report
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: security-scan-report
        path: api-security-report.md

    - name: Comment PR with results
      if: github.event_name == 'pull_request' && always()
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const report = fs.readFileSync('api-security-report.md', 'utf8');
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `## API Security Scan Results\n\n${report}`
          });

    - name: Fail if high severity issues found
      if: steps.scan.outcome == 'failure'
      run: exit 1
```

### Configuration Options

- `--fail-on <severity>`: Exit with code 1 if findings of specified severity or higher are found
- `--output json`: Generate machine-readable JSON output for further processing
- `--output markdown`: Generate human-readable Markdown reports
- `--severity <level>`: Set minimum severity level to report
- `--config .apiposture.json`: Use configuration file for suppressions and custom rules

### Exit Codes

- `0`: Scan completed successfully with no findings above the fail threshold
- `1`: Findings above the fail threshold were detected, or error during scan

## Project Structure

```
ApiPosture.php/
├── src/
│   ├── Core/
│   │   ├── Analyzer/          # Scan orchestrator
│   │   ├── Classification/    # Security classifier
│   │   ├── Config/            # Configuration loader
│   │   ├── Discovery/         # Laravel, Symfony, Slim discoverers
│   │   └── Model/             # Endpoint, Finding, ScanResult, Enums
│   ├── Rules/                 # 8 security rules + engine
│   ├── Output/                # Terminal, JSON, Markdown formatters
│   └── Command/               # CLI scan command
├── tests/
│   ├── Core/
│   ├── Rules/
│   ├── Output/
│   ├── Command/
│   └── Fixtures/              # Laravel, Symfony, Slim sample code
├── bin/apiposture              # CLI entry point
└── composer.json
```

## Building from Source

```bash
# Clone and install
git clone https://github.com/BlagoCuljak/ApiPosture.php.git
cd ApiPosture.php
composer install

# Run tests
vendor/bin/phpunit

# Run against sample fixtures
vendor/bin/apiposture scan tests/Fixtures/Laravel
vendor/bin/apiposture scan tests/Fixtures/Symfony --output json
vendor/bin/apiposture scan tests/Fixtures/Slim --output markdown
```

## Related Projects

- [ApiPosture](https://github.com/BlagoCuljak/ApiPosture) - .NET version (ASP.NET Core)
- [ApiPosture.Java](https://github.com/BlagoCuljak/ApiPosture.Java) - Java version (Spring Boot)
- [ApiPosture.Python](https://github.com/BlagoCuljak/ApiPosture.Python) - Python version (Django, Flask, FastAPI)
- [ApiPosture.Node.js](https://github.com/BlagoCuljak/ApiPosture.Node.js) - Node.js version (Express, Fastify, NestJS)
- [ApiPosture.Go](https://github.com/BlagoCuljak/ApiPosture.Go) - Go version (Gin, Echo, Chi)

## Contributing

We welcome contributions! Please:

- [Report a bug](https://github.com/BlagoCuljak/ApiPosture.php/issues/new)
- [Request a feature](https://github.com/BlagoCuljak/ApiPosture.php/issues/new)

## License

MIT
