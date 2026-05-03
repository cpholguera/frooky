// This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

import Java from "frida-java-bridge";
import type { FrookyConfig } from "frooky";
import { FrookyApp } from "../FrookyApp";
import { JavaHookResolver } from "./hook/javaHookResolver";

if (Java.available) {
  rpc.exports = {
    runFrookyAgent(frookyConfig: FrookyConfig) {
      globalThis.frooky = new FrookyApp("Android", new JavaHookResolver());
      frooky.loadFrookyConfig(frookyConfig);

      Java.perform(() => {
        frooky.executeHookOperations();
      });
    },
  };
} else {
  console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.");
}
