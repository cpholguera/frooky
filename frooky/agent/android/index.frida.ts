import Java from "frida-java-bridge";
import { FrookyAgent } from "../FrookyAgent";
import { FrookyConfig } from "../shared/frookyConfig";
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
