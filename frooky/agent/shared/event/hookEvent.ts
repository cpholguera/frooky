import type { DecodedValue } from "../decoders/decoder";
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

  /**
   * The category grouping this hook belongs to,
   * as defined in the hook configuration.
   */
  category?: string;

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
