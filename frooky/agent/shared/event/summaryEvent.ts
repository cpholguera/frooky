import type { Hook } from "frooky";
import { BaseEvent } from "./baseEvent";

/**
 * Represents a summary event created by frooky.
 *
 * Extends {@link BaseEvent} with summary fields.
 * ```
 */
export abstract class SummaryEvent extends BaseEvent {
  /**
   * The event type. Is always`"summary"` for this class and its subclasses.
   */
  readonly type = "summary" as const;

  /**
   * Successfully hooked functions / methods.
   */
  readonly hooks: Hook[];

  /**
   * Number of successfully hooked functions / methods.
   */
  readonly totalHooks: number;

  /**
   * Relevant errors for this summary.
   */
  readonly errors: Error[];

  /**
   * Number of errors.
   */
  readonly totalErrors: number;

  /**
   * Decoded return value from the hooked function / method.
   */
  readonly returnValue?: unknown;

  constructor(hooks: Hook[], errors?: Error[]) {
    super();
    this.hooks = hooks;
    this.totalHooks = hooks.length;
    this.errors = errors ?? [];
    this.totalErrors = this.errors.length;
  }
}
