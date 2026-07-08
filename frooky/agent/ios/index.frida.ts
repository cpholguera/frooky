import ObjC from "frida-objc-bridge";
import { FrookyAgent } from "../FrookyAgent";
import { DEFAULT_SETTING_LOG_TO, DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS } from "../shared/defaultValues";
import { InputFrookyConfig } from "../shared/frookyConfig";
import { IosHookManager } from "./hook/iosHookManager";
import { IosHookValidator } from "./hook/iosHookValidator";
import { IosStackTrace } from "./iosStackTrace";

var frookyConfigs: InputFrookyConfig[];

/**
 * IMPORTANT: This is just a place holder file!
 * At the moment, only native hooks can be used on iOS
 */
console.warn("!!! The frooky iOS agent only works wit native hooks at the moment !!!");
if (ObjC.available) {
  //%%% REPLACE START
  frookyConfigs = [{}] as InputFrookyConfig[];
  //%%% REPLACE STOP

  globalThis.frooky = new FrookyAgent(
    "iOS",
    new IosHookValidator(),
    new IosHookManager(IosStackTrace),
    IosStackTrace,
    "debug",
    DEFAULT_SETTING_LOG_TO,
    DEFAULT_SETTING_RESOLVER_TIMEOUT_SECONDS,
  );
  frooky.loadFrookyConfigs(frookyConfigs);
} else {
  console.error("[!] The objective-c environment is not available.");
}
