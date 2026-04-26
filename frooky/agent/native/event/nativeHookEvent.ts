import { HookEvent } from "../../shared/event/hookEvent";

/**
 * Represents a native hook event created by frooky.
 *
 * Extends {@link HookEvent} with native-specific fields for module and symbol information.
 * ```
 */
export class NativeHookEvent extends HookEvent {
  /** Module the hooked function is located in. */
  module: string;

  /** Symbol of the hooked function. */
  symbol: string;

  /** Address of the hooked function. */
  address?: NativePointer;

  constructor(module: string, symbol: string) {
    super();
    this.type += "-native";
    this.module = module;
    this.symbol = symbol;
  }
}
