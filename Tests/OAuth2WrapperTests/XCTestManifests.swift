import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(OAuth2WrapperTests.allTests),
    ]
}
#endif
