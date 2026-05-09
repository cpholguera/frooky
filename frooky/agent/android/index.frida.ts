// This file is used when the agent is run by frida. Hooks embedded into the agent at build time.
// !!!! Don't change this file, the build script will insert the actual frooky config here

import Java from "frida-java-bridge";
import type { FrookyConfig } from "frooky";
import { FrookyAgent } from "../FrookyAgent";
import { JavaHookManager } from "./hook/javaHookManager";
import { JavaHookValidator } from "./hook/javaHookValidator";

var frookyConfigs: FrookyConfig[];

if (Java.available) {
  //%%% REPLACE START
  frookyConfigs = [{}] as FrookyConfig[];
  //%%% REPLACE STOP

  Java.perform(() => {
    globalThis.frooky = new FrookyAgent("Android", new JavaHookValidator(), new JavaHookManager(), 3, "device");
    frooky.run(frookyConfigs);
  });
} else {
  console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.");
}
