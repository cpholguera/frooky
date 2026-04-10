import { type Hook, isJavaHook, isNativeHook, isObjcHook, type JavaHook, type NativeHook, type ObjcHook } from "frooky";
import type { JavaHookOperation } from "../../android/hook/javaHookRunner";
import { prettyPrintHook } from "../../shared/utils";
import type { HookOperation } from "./hookRunner";
import type { NativeHookOperation } from "./nativeHookRunner";


function isNativeHookOperation(op: HookOperation): op is NativeHookOperation {
  return op.hook.type === "native";
}

function isJavaHookOperation(op: HookOperation): op is JavaHookOperation {
  return op.hook.type === "java";
}


export class HookStore {
  private hooks: Hook[] = [];
  private hookOperations: HookOperation[] = [];

  addHook(hook: Hook): void {
    this.hooks.push(hook);
  }

  addHooks(hooks: Hook[]): void {
    for (const hook of hooks) {
      this.hooks.push(hook);
    }
  }

  addHookOperation(hookOperation: HookOperation): void {
    this.hookOperations.push(hookOperation);
  }

  addHookOperations(hookOperations: HookOperation[]): void {
    for (const hookOperation of hookOperations) {
      this.hookOperations.push(hookOperation);
    }
  }

  getHooks(): Hook[] {
    return [...this.hooks];
  }

  getHookOperations(): HookOperation[] {
    return [...this.hookOperations];
  }


  
  getNativeHookOperations(): NativeHookOperation[] {
    return this.hookOperations.filter(isNativeHookOperation);
  }

  getJavaHookOperations(): JavaHookOperation[] {
    return this.hookOperations.filter(isJavaHookOperation);
  }


  getNativeHooks(): NativeHook[] {
    return this.hooks.filter(isNativeHook);
  }

  getJavaHooks(): JavaHook[] {
    return this.hooks.filter(isJavaHook);
  }

  getObjcHooks(): ObjcHook[] {
    return this.hooks.filter(isObjcHook);
  }

  prettyPrintHooks(): string {
    let result: string = "";
    this.hooks.forEach((h) => {
      result += `${prettyPrintHook(h)}`;
    });
    return result;
  }
}
