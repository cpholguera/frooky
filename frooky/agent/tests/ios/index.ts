import { runTests } from "../testFramework.ts";

// The following test suite contains tests which test the test framework itself. It is disabled by default.
import "../testFramework.test.ts";

// Import the dynamically generated index.test.ts
import "../../shared/index.test";
import "./index.test.ts";

setTimeout(() => {
  runTests(send);
}, 1000);
