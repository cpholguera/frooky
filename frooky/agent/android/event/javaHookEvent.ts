import { HookEvent } from "../../shared/event/hookEvent";

export type JavaMemberType = "class" | "instance";

/**
 * Class representing a java hook event
 *
 * Extends {@link HookEvent} with hook-specific fields.
 * ```
 */
export class JavaHookEvent extends HookEvent {
  readonly javaClass: string;
  readonly method: string;
  readonly memberType: JavaMemberType;
  instanceId?: number;

  constructor(javaClass: string, method: string, memberType: JavaMemberType) {
    super();
    this.type += "-java";
    this.javaClass = javaClass;
    this.method = method;
    this.memberType = memberType;
  }
}
