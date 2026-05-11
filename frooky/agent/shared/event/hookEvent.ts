import { DecodedValue } from "../decoders/decodedValue";
import { DecodedArgs } from "../hook/hookManager";
import { BaseEvent } from "./baseEvent";

/**
 * Abstract class for all hook events created by frooky.
 *
 * Extends {@link BaseEvent} with hook-specific fields.
 * ```
 */
export abstract class HookEvent extends BaseEvent {
  /**
   * The event type.
   */
  type = "hook";

  /** Stack trace captured at the point of interception. */
  stackTrace?: string[];

  /**
   * Decoded input argument values passed to the hooked function / method.
   */
  argsOnEnter?: DecodedValue[];

  /**
   * Decoded input argument values passed to the hooked function / method.
   */
  argsOnExit?: DecodedValue[];

  /**
   * Decoded return value from the hooked function / method.
   */
  returnValue?: DecodedValue;

  constructor(decodedArgs?: DecodedArgs, returnValue?: DecodedValue, stackTrace?: string[]) {
    super();
    if (decodedArgs) {
      this.argsOnEnter = decodedArgs.enter;
      this.argsOnExit = decodedArgs.exit;
    }
    this.returnValue = returnValue;
    this.stackTrace = stackTrace;
  }
}
