import { HookEvent } from "../../shared/event/hookEvent";
import type { FieldType } from "../hook/javaHookImpl";

/**
 * Class representing a java hook event
 *
 * Extends {@link HookEvent} with hook-specific fields.
 * ```
 */
export class JavaHookEvent extends HookEvent {
  readonly javaClass: string;
  readonly method: string;
  readonly fieldType: FieldType;

  constructor(javaClass: string, method: string, fieldType: FieldType) {
    super();
    this.type += "-java";
    this.javaClass = javaClass;
    this.method = method;
    this.fieldType = fieldType;
  }
}
