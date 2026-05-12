import Java from "frida-java-bridge";
import { Param } from "../../shared/decoders/decodable";
import { Hook } from "../../shared/hook/hook";

/**
 * Contains all information to hook a java method
 *
 * @public
 */
export interface JavaHook extends Hook {
  method: Java.Method;
  methodName: string;
  params?: Param[];
}

export function isJavaHook(hook: Hook): hook is JavaHook {
  return "overloads" in hook;
}
