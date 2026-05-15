import Java from "frida-java-bridge";
import { FrookyAgent } from "../FrookyAgent";
import { DEFAULT_SETTING_LOG_TO, DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS } from "../shared/defaultValues";
import { InputFrookyConfig } from "../shared/frookyConfig";
import { JavaHookManager } from "./hook/javaHookManager";
import { JavaHookValidator } from "./hook/javaHookValidator";

var frookyConfigs: InputFrookyConfig[];

if (Java.available) {
  //%%% REPLACE START
  frookyConfigs = [{}] as InputFrookyConfig[];
  //%%% REPLACE STOP

  Java.perform(() => {
    globalThis.frooky = new FrookyAgent(
      "Android",
      new JavaHookValidator(),
      new JavaHookManager(),
      "debug",
      DEFAULT_SETTING_LOG_TO,
      DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS,
    );
    frooky.loadFrookyConfigs(frookyConfigs);
  });
} else {
  console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.");
}
