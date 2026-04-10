import { type Hook, isJavaHook, isNativeHook, isObjcHook, type JavaHook, type NativeHook, type ObjcHook } from "frooky";
import type { JavaHookOperation } from "../../android/hook/javaHookRunner";
import { prettyPrintHook } from "../../shared/utils";
import type { HookOperation } from "./hookRunner";
import type { NativeHookOperation } from "./nativeHookRunner";

export class HookStore {
  private hooks: Hook[] = [];

  addHook(hook: Hook): void {
    this.hooks.push(hook);
  }

  addHooks(hooks: Hook[]): void {
    for (const hook of hooks) {
      this.hooks.push(hook);
    }
  }

  getHooks(): Hook[] {
    return [...this.hooks];
  }

  getHookOperations(): HookOperation[] {
    return this.hooks
      .map(hook => hook.hookOp)
      .filter((hookOp): hookOp is HookOperation => hookOp !== undefined);
  }

  getNativeHookOperations(): NativeHookOperation[] {
    return this.getNativeHooks()
      .map(hook => hook.hookOp)
      .filter((hookOp): hookOp is NativeHookOperation => hookOp !== undefined);
  }

  getJavaHookOperations(): JavaHookOperation[] {
    console.log("aaaa ")
    console.log(JSON.stringify(this.hooks, null, 2));
    return this.getJavaHooks()
      .map(hook => hook.hookOp)
      .filter((hookOp): hookOp is JavaHookOperation => hookOp !== undefined);
  }

  // TODO: ObjcHookOperation needs to be implemented
  // getObjcHookOperations(): ObjcHookOperation[] {
  //   return this.getObjcHooks()
  //     .map(hook => hook.hookOp)
  //     .filter((hookOp): hookOp is ObjcHookOperation => hookOp !== undefined);
  // }

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
