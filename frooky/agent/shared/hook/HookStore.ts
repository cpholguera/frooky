import { Hook, NativeHook, ObjCHook, JavaHook } from "frooky";
import { prettyPrintHook } from "shared/utils";
import { HookOperation } from "./HookRunner";

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

  getNativeHookOperations(): HookOperation[] {
    return this.hookOperations.filter((op) => op.hook.type === "native");
  }

  getJavaHookOperations(): HookOperation[] {
    return this.hookOperations.filter((op) => op.hook.type === "java");
  }

  getObjcHookOperations(): HookOperation[] {
    return this.hookOperations.filter((op) => op.hook.type === "objc");
  }

  getNativeHooks(): NativeHook[] {
    return this.hooks.filter((hook) => hook.type === "native");
  }

  getJavaHooks(): JavaHook[] {
    return this.hooks.filter((hook) => hook.type === "java");
  }

  getObjcHooks(): ObjCHook[] {
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
