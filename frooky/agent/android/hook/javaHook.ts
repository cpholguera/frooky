import Java from "frida-java-bridge";
import { Hook } from "../../shared/hook/hook";
import type { JavaParam } from "./javaParam";

/**
 * Describes a specific Java method overload.
 *
 * @public
 */
export interface JavaOverload {
  /**
   * Parameter definitions for this overload.
   */
  params: JavaParam[];
}

/**
 * Contains all information to hook a java method
 *
 * @public
 */
export interface JavaHook extends Hook {
  method: Java.Method;
  methodName: string;
  overloads: JavaOverload[];
}

export function isJavaHook(hook: Hook): hook is JavaHook {
  return "overloads" in hook;
}
