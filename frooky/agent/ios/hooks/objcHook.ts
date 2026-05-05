import ObjC from "frida-objc-bridge";
import { Hook } from "../../shared/hook/hook";

/**
 * Contains all information to hook a java method
 *
 * @public
 */
export interface ObjcHook extends Hook {
  object: ObjC.Object;
  method: ObjC.ObjectMethod;
}

export function isObjcHook(hook: Hook): hook is ObjcHook {
  return "object" in hook;
}
