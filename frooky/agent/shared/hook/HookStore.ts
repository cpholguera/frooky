import { Hook, NativeHook, ObjCHook, JavaHook } from "frooky";
import { prettyPrintHook } from "shared/utils";

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
