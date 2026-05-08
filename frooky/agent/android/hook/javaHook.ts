import Java from "frida-java-bridge";
import { Hook } from "../../shared/hook/hook";
import type { JavaParam } from "./javaParam";

/**
 * Contains all information to hook a java method
 *
 * @public
 */
export interface JavaHook extends Hook {
  method: Java.Method;
  methodName: string;
  params: JavaParam[];
}

export function isJavaHook(hook: Hook): hook is JavaHook {
  return "overloads" in hook;
}
