// This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

import Java from "frida-java-bridge";
import { JavaHookManager, JavaHookValidator } from "frooky/android";
import { FrookyConfig } from "frooky/shared";
import { FrookyAgent } from "../FrookyAgent";

if (Java.available) {
  rpc.exports = {
    runFrookyAgent(frookyConfig: FrookyConfig[]) {
      Java.perform(() => {
        globalThis.frooky = new FrookyAgent("Android", new JavaHookValidator(), new JavaHookManager(), 3, "device");
        frooky.run(frookyConfig);
      });
    },
  };
} else {
  console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.");
}
