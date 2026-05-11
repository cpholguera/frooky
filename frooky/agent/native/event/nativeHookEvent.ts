import { DecodedValue } from "../../shared/decoders/decodedValue";
import { HookEvent } from "../../shared/event/hookEvent";
import { DecodedArgs } from "../../shared/hook/hookManager";
import { NativeHook } from "../hook/nativeHook";

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

  constructor(hook: NativeHook, decodedArgs?: DecodedArgs, returnValue?: DecodedValue, stackTrace?: string[]) {
    super(decodedArgs, returnValue, stackTrace);
    this.type += "-native";
    this.module = hook.module.name;
    this.symbol = hook.symbolName;
  }
}
