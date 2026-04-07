import type { FrookyConfig, Hook, JavaHook, NativeHook, ObjCHook, Platform } from "frooky";
import z from "zod";
import { javaHookSchema } from "../../types/hook/javaHook.zod";
import { objCHookSchema } from "../../types/hook/objcHook.zod";
import { nativeHookSchema } from "../../types/hook/nativeHook.zod";
import { validateHooks } from "./hookValidator";



function getHookSchema(hook: Hook){
  if ("javaClass" in hook) { return javaHookSchema }
  if ("objcClass" in hook) { return objCHookSchema }
  if ("nativeClass" in hook) { return nativeHookSchema }

  throw Error("Unknown hook type detected.")
}


export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform){
    frooky.log.info(`Validating frooky configuration for platform ${platform}`)
    frooky.log.info(`frooky configuration:\n${JSON.stringify(frookyConfig, null, 2)}`)

    // validate metadata
    if (frookyConfig.metadata){
        frooky.log.info(`frooky config metadata:\n${JSON.stringify(frookyConfig.metadata, null, 2)}`)
    } else {
       frooky.log.warn("This frooky configuration does not have metadata. Consider adding them for better results.")
    }
 
    const validHooks: Hook[] = validateHooks(frookyConfig);



    frooky.log.info("  Hook configuration successfully validated.")
}