import { JavaHookOperation } from "android/hook/javaHookRunner";
import { Hook, JavaHook, NativeHook, ObjcHook, ObjCHook } from "frooky";
import { prettyPrintHook } from "../../shared/utils";
import { HookOperation } from "./hookRunner";
import { NativeHookOperation } from "./nativeHookRunner";


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


  // TODO: implement Objective-C


  getNativeHooks(): NativeHook[] {
    return this.hooks.filter((hook) => hook.type === "native");
  }

  getJavaHooks(): JavaHook[] {
    return this.hooks.filter((hook) => hook.type === "java");
  }

  getObjcHooks(): ObjcHook[] {
    return this.hooks.filter((hook) => hook.type === "objc");
  }

  prettyPrintHooks(): string {
    let result: string = "";
    this.hooks.forEach((h) => {
      result += `${prettyPrintHook(h)}`;
    });
    return result;
  }
}
