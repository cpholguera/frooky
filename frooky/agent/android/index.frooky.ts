import Java from "frida-java-bridge";
import { FrookyAgent } from "../FrookyAgent";
import { DEFAULT_SETTING_LOG_LEVEL, DEFAULT_SETTING_LOG_TO, DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS } from "../shared/defaultValues";
import { InputFrookyConfig } from "../shared/frookyConfig";
import { LogLevel, LogTo } from "../shared/logger";
import { JavaHookManager } from "./hook/javaHookManager";
import { JavaHookValidator } from "./hook/javaHookValidator";

rpc.exports = {
  initFrookyAgent(logLevel?: LogLevel, logTo?: LogTo, resolverTimeoutSeconds?: number) {
    if (Java.available) {
      globalThis.frooky = new FrookyAgent(
        "Android",
        new JavaHookValidator(),
        new JavaHookManager(),
        logLevel ?? DEFAULT_SETTING_LOG_LEVEL,
        logTo ?? DEFAULT_SETTING_LOG_TO,
        resolverTimeoutSeconds ?? DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS,
      );
    } else {
      console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.");
    }
  },
  loadFrookyConfigs(frookyConfigs: InputFrookyConfig[]) {
    Java.perform(() => {
      frooky.loadFrookyConfigs(frookyConfigs);
    });
  },
};
