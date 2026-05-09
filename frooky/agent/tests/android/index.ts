import Java from "frida-java-bridge";
import { runTests } from "../agent-test-framework";

// Import all test files
import "../../shared/utils.test";
import "./platform.test";

// init global logger

Java.perform(() => {
  setTimeout(() => {
    runTests(send);
  }, 1000);
});
