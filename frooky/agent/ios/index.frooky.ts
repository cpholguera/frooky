import ObjC from "frida-objc-bridge";
import { FrookyAgent } from "../FrookyAgent";
import { DEFAULT_SETTING_LOG_LEVEL, DEFAULT_SETTING_LOG_TO, DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS } from "../shared/defaultValues";
import { InputFrookyConfig } from "../shared/frookyConfig";
import { LogLevel, LogTo } from "../shared/logger";
import { IosHookManager } from "./hook/iosHookManager";
import { IosHookValidator } from "./hook/iosHookValidator";
import { IosStackTrace } from "./iosStackTrace";

/**
 * IMPORTANT: This is just a place holder file!
 * At the moment, only native hooks can be used on iOS
 */
console.warn("!!! The frooky iOS agent only works wit native hooks at the moment !!!");
rpc.exports = {
  initFrookyAgent(logLevel?: LogLevel, logTo?: LogTo, resolverTimeoutSeconds?: number) {
    if (ObjC.available) {
      globalThis.frooky = new FrookyAgent(
        "iOS",
        new IosHookValidator(),
        new IosHookManager(IosStackTrace),
        IosStackTrace,
        logLevel ?? DEFAULT_SETTING_LOG_LEVEL,
        logTo ?? DEFAULT_SETTING_LOG_TO,
        resolverTimeoutSeconds ?? DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS,
      );
    } else {
      console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.");
    }
  },
  loadFrookyConfigs(frookyConfigs: InputFrookyConfig[]) {
    frooky.loadFrookyConfigs(frookyConfigs);
  },
};
