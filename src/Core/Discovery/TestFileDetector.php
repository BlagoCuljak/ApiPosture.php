<?php

declare(strict_types=1);

namespace ApiPosture\Core\Discovery;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;

/**
 * Detects automated-test sources. Routes registered inside tests
 * ($this->router->get(...), Route::get(...) in setUp) are fixtures, not real endpoints.
 */
final class TestFileDetector
{
    private const TEST_FILE_SUFFIXES = ['Test.php', 'TestCase.php', 'Cest.php'];

    private const TEST_BASE_CLASSES = ['testcase', 'kerneltestcase', 'webtestcase', 'apitestcase'];

    /**
     * @param Node[] $ast
     */
    public static function isTestFile(string $filePath, array $ast): bool
    {
        $base = basename(str_replace('\\', '/', $filePath));
        foreach (self::TEST_FILE_SUFFIXES as $suffix) {
            if (str_ends_with($base, $suffix)) {
                return true;
            }
        }

        // Test classes that do not follow the *Test.php naming convention.
        $finder = new NodeFinder();
        $testClass = $finder->findFirst($ast, function (Node $node) {
            if (!$node instanceof Stmt\Class_ || $node->extends === null) {
                return false;
            }
            $parent = strtolower($node->extends->getLast());
            return in_array($parent, self::TEST_BASE_CLASSES, true);
        });

        return $testClass !== null;
    }
}
