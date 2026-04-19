import { type Hook, isJavaHook, isNativeHook, isObjcHook, type JavaHook, type NativeHook, type ObjcHook } from "frooky";
import { prettyPrintHook } from "../../shared/utils";

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
