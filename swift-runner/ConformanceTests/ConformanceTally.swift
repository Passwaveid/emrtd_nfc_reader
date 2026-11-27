import XCTest

/// XCTest sees one test method per layer; the per-case bookkeeping that a
/// RUNS.md entry needs lives here and is printed for run.sh to extract.
class ConformanceTallyTestCase: XCTestCase {
    struct Tally {
        var passed = 0
        var failed = 0
        var skipped = 0
        var cases: Int { passed + failed + skipped }
    }

    private var currentCaseFailed = false

    override func record(_ issue: XCTIssue) {
        currentCaseFailed = true
        super.record(issue)
    }

    /// Runs one case as an XCTContext activity and tallies it from the
    /// issues recorded while it ran.
    func runConformanceCase(
        _ label: String, layer: String, tally: inout Tally, _ body: () -> Void
    ) {
        currentCaseFailed = false
        XCTContext.runActivity(named: label) { _ in body() }
        if currentCaseFailed {
            tally.failed += 1
            print("[conformance] FAIL (swift) \(layer): \(label)")
        } else {
            tally.passed += 1
            print("[conformance] PASS (swift) \(layer): \(label)")
        }
    }

    func printSummary(layer: String, tally: Tally) {
        print(
            "[conformance] SUMMARY (swift) \(layer): cases=\(tally.cases) "
                + "passed=\(tally.passed) failed=\(tally.failed) skipped=\(tally.skipped)")
    }
}
