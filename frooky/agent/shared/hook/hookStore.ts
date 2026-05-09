import { isJavaHook, JavaHook } from "frooky/android";
import { isObjcHook, ObjcHook } from "frooky/ios";
import { isNativeHook, NativeHook } from "frooky/native";
import { Hook } from "frooky/shared";

export class HookStore {
  private hooks: Hook[] = [];

  addHook(hook: Hook): void {
    this.hooks.push(hook);
  }

  addHooks(hooks: Hook[]): void {
    this.hooks = [...hooks];
  }

  getHooks(): Hook[] {
    return [...this.hooks];
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
}
