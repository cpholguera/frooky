import Java from "frida-java-bridge";
import { HookEvent } from "../../shared/event/hookEvent";
import { FieldType } from "../hook/javaHookImpl";

/**
 * Class representing a java hook event
 *
 * Extends {@link HookEvent} with hook-specific fields.
 * ```
 */
export class JavaHookEvent extends HookEvent {
  readonly javaClassName: string;
  readonly method: string;
  readonly fieldType: FieldType;

  constructor(method: Java.Method, fieldType: FieldType) {
    super();
    this.type += "-java";
    this.javaClassName = method.holder.$className;
    this.method = method.methodName;
    this.fieldType = fieldType;
  }
}
