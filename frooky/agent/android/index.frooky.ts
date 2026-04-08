// This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

import Java from "frida-java-bridge";
import type { FrookyConfig } from "frooky";
import { FrookyApp } from "../FrookyApp";
import { AndroidHookResolver } from "./resolver/AndroidHookResolver";

if (Java.available) {
  rpc.exports = {
    runFrookyAgent(frookyConfig: FrookyConfig) {
      globalThis.frooky = new FrookyApp("Android", new AndroidHookResolver());
      frooky.loadFrookyConfig(frookyConfig);
    }
  };
} else {
  console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.")
}