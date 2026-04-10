import { HookEvent } from "./hookEvent";

/**
 * Represents a native hook event created by frooky.
 *
 * Extends {@link HookEvent} with native-specific fields for module and symbol information.
 * ```
 */
export class NativeHookEvent extends HookEvent {
  /** Module the hooked function is located in. */
  readonly module: string;

  /** Symbol of the hooked function. */
  readonly symbol: string;

  constructor(module: string, symbol: string, category: string, stackTrace: string, args?: unknown[], returnValue?: unknown) {
    super(category, stackTrace, args, returnValue);
    this.module = module;
    this.symbol = symbol;
  }
}
