import type { BaseDecoder } from "../decoders/baseDecoder";
import type { ParamDecoderSettings } from "../decoders/decoderSettings";

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
 * Frida-compatible type of the parameter.
 *
 * @example "java.lang.String"
 * @example "[Ljava.lang.Object;"
 * @example "[Z"
 * @example "int"
 *
 * @public
 */
export type ParamType = string;

/**
 * Parameter name.
 *
 * @example "username"
 * @example "buffer"
 * @example "url"
 *
 * @public
 */
export type ParamName = string;

/**
 * Normalized parameter descriptor used internally during function hooking.
 *
 * For input, prefer the shorthand {@link ParamInput} forms, which are
 * automatically normalized via {@link normalizeParam}.
 *
 * @example
 * { type: "java.lang.String" }
 * @example
 * { type: "java.lang.String", name: "username", options: { decodeAt: "exit" } }
 *
 * @public
 */
export interface Param {
  /** Declared parameter type (primitive, array, class, interface, or native type). */
  type: ParamType;
  /** Optional parameter name, e.g. `"username"` or `"age"`. */
  name?: ParamName;
  /** Cached decoder, resolved on first decode of this parameter type. */
  // biome-ignore lint/suspicious/noExplicitAny: decoder is a cache for any concrete BaseDecoder; variance on TValue prevents using unknown here
  decoder?: BaseDecoder<any, any>;
  /**
   * Settings applied when running the decoder.
   */
  decoderSettings: ParamDecoderSettings;
}
