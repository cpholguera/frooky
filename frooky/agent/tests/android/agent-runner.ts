import Java from "frida-java-bridge";
import { runTests } from "../agent-test-framework";

// Import all test files
import "./test-decoder";
import "./test-runtime";
import "./test-util";

// Import shared tests
import "../shared/import-shared-tests";

// init global logger

Java.perform(() => {
  setTimeout(() => {
    runTests(send);
  }, 1000);
});
