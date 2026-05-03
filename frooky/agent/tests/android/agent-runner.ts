import Java from "frida-java-bridge";
import { runTests } from "../agent-test-framework";

// Import all test files
import "../shared/test-testing";
import "./test-decoder";
import "./test-runtime";
import "./test-util";

Java.perform(() => {
  setTimeout(() => {
    runTests(send);
  }, 1000);
});
