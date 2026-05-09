import Java from "frida-java-bridge";
import { FrookyAgent } from "../FrookyAgent";
import { FrookyConfig } from "../shared";
import { JavaHookManager } from "./hook/javaHookManager";
import { JavaHookValidator } from "./hook/javaHookValidator";

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
