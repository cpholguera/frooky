import type { NativeHook } from "frooky";
import { registerNativeHook, registerNativeHooks, resolveNativeSymbol } from "../../android/legacy/android-agent";
import type { HookEntry, HookRunner } from "./hookRunner";


export interface NativeHookEntry extends HookEntry {
  symbol: string;               // Todo needs to be refactored when legacy code is refactored
  symbolAddress: NativePointer
}

export class NativeHookRunner implements HookRunner {
  executeHooking(hooks: NativeHook[]): void {

    var nativeHookEntryArray: NativeHookEntry[] = [];


    frooky.log.info(`Executing native hook operations`)
    hooks.forEach((h: NativeHook) => {
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!! 
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      // Also, the naming is pretty confusing, should be refactored later
      // We should use the validators for the result set, just like with config and hook validations
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

      frooky.log.info(`Building hook operations for native`)
      nativeHookEntryArray.push(...resolveNativeSymbol(h))

    });
    frooky.log.info(`Hook operations for the following hook built: ${JSON.stringify(nativeHookEntryArray, null, 2)}`)
    frooky.log.info(`Run native hooking`)
    registerNativeHooks(nativeHookEntryArray)
  }
}  
