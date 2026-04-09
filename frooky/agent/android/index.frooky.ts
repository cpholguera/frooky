// This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

import Java from "frida-java-bridge";
import type { FrookyConfig } from "frooky";
import { FrookyApp } from "../FrookyApp";
import { JavaHookRunner } from "./hook/javaHookRunner";

if (Java.available) {
  rpc.exports = {
    runFrookyAgent(frookyConfig: FrookyConfig) {
      globalThis.frooky = new FrookyApp("Android", new JavaHookRunner());
      frooky.loadFrookyConfig(frookyConfig);

      Java.perform(() => {
        frooky.prepareHookOperation();
        frooky.executeHookOperations();
      }) 
      
    }
  };
} else {
  console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.")
}