import { buildHookOperations, registerHook } from "../legacy/android-agent"
import type { HookEntry, HookRunner } from "../../shared/hook/hookRunner"
import { JavaHook } from "./javaHook"


export interface JavaHookEntry extends HookEntry {
  class: string,
  method: any,           // Todo needs to be refactored when legacy code is refactored
  overloadIndex: number,
  args: string[],
  maxFrames: number,
}

export class JavaHookRunner implements HookRunner {
  executeHooking(hooks: JavaHook[]): void {

    var javaHookEntryArray: JavaHookEntry[] = [];

    frooky.log.info(`Executing Android hook operations`)


    hooks.forEach((h: JavaHook) => {
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!! 
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      // Also, the naming is pretty confusing, should be refactored later
      // We should use the validators for the result set, just like with config and hook validations
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

      javaHookEntryArray.push(...buildHookOperations(h));

    });
    frooky.log.info(`Hook operations for the following hook built: ${JSON.stringify(javaHookEntryArray, null, 2)}`)
    frooky.log.info(`Run Android hooking`)
    registerHook(javaHookEntryArray)
  }
} 



