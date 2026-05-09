import Java from "frida-java-bridge";
import { runTests } from "../testFramework";

// The following test suite contains tests which test the test framework itself. It is disabled by default.
import "../testFramework.test.ts";

// Import the dynamically generated index.test.ts
import "../../shared/index.test";
import "./index.test";

Java.perform(() => {
  setTimeout(() => {
    runTests(send);
  }, 1000);
});
