import { BaseDecoder } from "./baseDecoder";
import { DecoderSettings } from "./decoderSettings";

/**
 * Specifies when a decoder should be applied during function execution.
 *
 * @example "enter" - Decode when the function/method is entered (before execution)
 * @example "exit" - Decode when the function/method returns (after execution)
 * @example "both" - Decode at both times
 *
 * @public
 */
export type DecodeAt = "enter" | "exit" | "both";

/**
 * Base structure for a type that can be decoded.
 */
export interface DecodableType {
  /** Declared parameter type such as primitive type, array, class, interface, or native structs. */
  type: string;

  /**
   * Cached decoder, resolved on first decode of this parameter type.  Used to avoid repeated decoder lookups.
   */
  decoder?: BaseDecoder<any, any>;

  /** Settings applied when running the decoder. */
  settings: DecoderSettings;
}

/**
 * Describes a parameter of a function or method signature.
 *
 * Extends {@link DecodableType} with an optional name and controls when decoding is applied (on function entry, exit, or both).
 */
export interface Param extends DecodableType {
  /** Optional parameter name, e.g. `"username"` or `"age"`. */
  name?: string;

  /**
   * When the decoder should be applied.
   *
   * @defaultValue "enter"
   * @example "exit"
   * @example "both"
   */
  decodeAt?: DecodeAt;
}

/** Describes the return type of a function or method signature. */
export interface RetType extends DecodableType {}