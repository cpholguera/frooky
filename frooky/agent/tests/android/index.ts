import Java from "frida-java-bridge";
import { AndroidHookManager } from "../../android/hook/androidHookManager.ts";
import { AndroidHookValidator } from "../../android/hook/androidHookValidator.ts";
import { FrookyAgent } from "../../FrookyAgent.ts";
import { runTests } from "../testFramework";

// The following test suite contains tests which test the test framework itself. It is disabled by default.
import "../testFramework.test.ts";

// Import the dynamically generated index.test.ts
import { AndroidStackTrace } from "../../android/androidStackTrace.ts";
import "../../android/index.test";
import "../../native/index.test";
import "../../shared/index.test";
import "./index.test";

Java.perform(() => {
  setTimeout(() => {
    globalThis.frooky = new FrookyAgent(
      "Android",
      new AndroidHookValidator(),
      new AndroidHookManager(AndroidStackTrace),
      AndroidStackTrace,
      "none",
      "console",
    );
    runTests(send);
  }, 1000);
});
