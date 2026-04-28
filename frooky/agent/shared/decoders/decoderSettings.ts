import type { DecodeAt } from "../hook/param";

/**
 * Decoder settings.
 *
 * @public
 */
export type DecoderSettings = {
  /**
   * Maximum recursion depth for nested structure decoding.
   *
   * @example 10
   */
  maxRecursion: number;

  /**
   * Maximum number of elements to decode in a collection or buffer.
   *
   * @example 1000
   */
  decodeLimit: number;

  /**
   * When enabled, frooky tries to guess the type of a value in case it is not declared in the hook, or it is not possible to deduct it at runtime.
   *
   * @defaultValue false
   */
  magicDecode: boolean;

  /**
   * When enabled, the decoders are instructed to prioritize speed over details. Mostly, this mean avoiding expensive Frida <-> native roundtrip.
   *
   * @defaultValue false
   */
  fastDecode: boolean;

  /**
   * When the decoder should be applied.
   *
   * @defaultValue "enter"
   * @example "exit"
   * @example "both"
   */
  decodeAt: DecodeAt;

  /**
   * Extra arguments passed to the decoder. They must be a valid parameter name.
   *
   * @defaultValue []
   * @example [ "ctxPointer" ]
   * @example [ "inBuffer", "bufferLength" ]
   */
  decoderArgs: string[];
};
