import { BaseEvent } from "./baseEvent";

/**
 * Abstract class for all hook events created by frooky.
 *
 * Extends {@link BaseEvent} with hook-specific fields.
 * ```
 */
export abstract class HookEvent extends BaseEvent {
	/**
	 * The event type. Is always`"hook"` for this class and its subclasses.
	 */
	readonly type = "hook" as const;

	/**
	 * The category grouping this hook belongs to,
	 * as defined in the hook configuration.
	 */
	readonly category: string;

	/** Stack trace captured at the point of interception. */
	readonly stackTrace: string;

	/**
	 * Decoded input arguments passed to the hooked function / method.
	 */
	readonly args?: unknown[];

	/**
	 * Decoded return value from the hooked function / method.
	 */
	readonly returnValue?: unknown;

	constructor(
		category: string,
		stackTrace: string,
		args?: unknown[],
		returnValue?: unknown,
	) {
		super();
		this.category = category;
		this.stackTrace = stackTrace;
		this.args = args;
		this.returnValue = returnValue;
	}
}
