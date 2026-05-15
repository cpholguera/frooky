import { JavaHook, isJavaHook } from "../../android/hook/javaHook";
import { ObjcHook, isObjcHook } from "../../ios/hooks/objcHook";
import { NativeHook, isNativeHook } from "../../native/hook/nativeHook";
import { Hook } from "./hook";

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
