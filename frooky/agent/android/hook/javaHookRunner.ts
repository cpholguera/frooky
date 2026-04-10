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
    console.log("assfdasdfasdgasdgadsfg")
    console.log(JSON.stringify(hooks))

    var javaHookEntryArray: JavaHookEntry[] = [];

    frooky.log.info(`Executing Android hook operations`)


    hooks.forEach((h: JavaHook) => {
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!! 
      // TODO: JUMP to legacy code
      // Needs to be refactored later
      // Also, the naming is pretty confusing, should be refactored later
      // We should use the validators for the result set, just like with config and hook validations
      // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

      frooky.log.info(`Building hook operations for Android`);
      console.log("aaaaa")
      javaHookEntryArray.push(buildHookOperations(h));

    });
    frooky.log.info(`Hook operations for the following hook built: ${JSON.stringify(javaHookEntryArray)}`)
    frooky.log.info(`Run Android hooking`)
    registerHook(javaHookEntryArray)
  }
} 



