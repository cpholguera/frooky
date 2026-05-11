import { DecoderSettings } from "../frookySettings";

/**
 * Base structure for a type that can be decoded.
 */
export interface Decodable {
  /** Declared parameter type such as primitive type, array, class, interface, or native structs. */
  type: string;

  /** Optional name for the value. */
  name?: string;

  /** Settings applied when running the decoder. */
  decoderSettings: DecoderSettings;
}

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
 * Describes a parameter of a function or method signature.
 *
 * Extends {@link Decodable} with an optional name and controls when decoding is applied (on function entry, exit, or both).
 */
export interface Param extends Decodable {
  /**
   * When the decoder should be applied.
   *
   * @defaultValue "enter"
   * @example "exit"
   * @example "both"
   */
  decodeAt: DecodeAt;
}

/**
 * Is used for for return types. Not technically necessary, but make code more readable.
 *
 */
export interface RetType extends Decodable {}
