import { HookEvent } from "../../shared/event/hookEvent";

/**
 * Class representing a java hook event
 *
 * Extends {@link HookEvent} with hook-specific fields.
 * ```
 */
export class JavaHookEvent extends HookEvent {
	readonly javaClass: string;

	constructor(javaClass: string) {
		super("java");
		this.javaClass = javaClass;
	}
}
