import type { BaseDecoder } from "../decoders/baseDecoder";

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
 * Decoder options for a parameter.
 *
 * @public
 */
export interface ParamOptions {
  /**
   * Overwrites the standard decoder lookup and uses the custom decoder.
   *
   * @example [ "android.content.IntentFlagDecoder." ]
   */
  decoder?: string;

  /**
   * When the decoder should be applied.
   *
   * @defaultValue "enter"
   * @example [ "exit" ]
   * @example [ "both" ]
   */
  decodeAt?: DecodeAt;

  /**
   * Extra arguments passed to the decoder. They must be a valid parameter name.
   *
   * @example [ "username" ]
   * @example [ "ctxPointer" ]
   * @example [ "inBuffer", "bufferLength" ]
   */
  decoderArgs?: string[];
}

/**
 * Canonical definition of a parameter to be decoded during function hooking.
 *
 * This is the normalized form used internally. If you are providing parameters
 * as input, you may also use the shorthand {@link ParamInput} forms, which are
 * automatically normalized via {@link normalizeParam}.
 *
 * @example
 * // Minimal – type only
 * { type: "java.lang.String" }
 *
 * @example
 * // With name and options
 * { type: "java.lang.String", name: "username", options: { decodeAt: "exit" } }
 *
 * @public
 */
export interface ParamDefinition {
  /**
   * Type of the parameter declared in the frooky file.
   * Can be fundamental, primitive, array, interfaces or classes.
   */
  type: ParamType;
  /** Optional name for the parameter, e.g. `"username"`. */
  name?: ParamName;
  /** Optional decoder options controlling when and how the parameter is decoded. */
  options?: ParamOptions;
  /** Optional decoder. Is set the first time a value of this parameter type is decoded */
  decoder?: BaseDecoder<any, Param>;
}

/**
 * Parameter definition intended for the internal usage
 *
 * @example { type: "java.lang.String", name: "value", options: { decodeAt: "exit" } }
 *
 * @public
 */
export type Param = ParamDefinition;
