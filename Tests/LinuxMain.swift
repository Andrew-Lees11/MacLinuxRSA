import XCTest

import OpenSSLSeckeyTests

var tests = [XCTestCaseEntry]()
tests += OpenSSLSeckeyTests.allTests()
XCTMain(tests)