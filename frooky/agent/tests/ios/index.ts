import { runTests } from "../agent-test-framework";

// Import all ios test files
import "./smoke.test";

setTimeout(() => {
  runTests(send);
}, 1000);
