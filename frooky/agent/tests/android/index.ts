import Java from "frida-java-bridge";
import { JavaHookManager } from "../../android/hook/javaHookManager.ts";
import { JavaHookValidator } from "../../android/hook/javaHookValidator.ts";
import { FrookyAgent } from "../../FrookyAgent.ts";
import { runTests } from "../testFramework";

// The following test suite contains tests which test the test framework itself. It is disabled by default.
import "../testFramework.test.ts";

// Import the dynamically generated index.test.ts
import "../../shared/index.test";
import "./index.test";

Java.perform(() => {
  setTimeout(() => {
    globalThis.frooky = new FrookyAgent("Android", new JavaHookValidator(), new JavaHookManager(), 0, "device");
    runTests(send);
  }, 1000);
});
