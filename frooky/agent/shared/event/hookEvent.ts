import { BaseEvent, DecodedValue } from "frooky/shared";

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
  args?: DecodedValue[];

  /**
   * Decoded return value from the hooked function / method.
   */
  returnValue?: DecodedValue;
}
