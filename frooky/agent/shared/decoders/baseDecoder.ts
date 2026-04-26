import type { Param } from "../hook/param";
import type { DecodedValue } from "./decodedValue";

/**
 * Base interface for value decoders.
 *
 * @template TValue - The raw input type to decode.
 * @template TParam - The parameter descriptor type, extending {@link Param}.
 */
export interface BaseDecoder<TValue, TParam extends Param> {
  /**
   * Decodes a raw value into a {@link DecodedValue}.
   *
   * @param value - The raw value to decode.
   * @param param - Parameter descriptor carrying metadata such as the declared name, type, and an optional cached decoder.
   * @param magicDecode - When `true`, attempts best-effort type inference if no explicit decoder is available via `param.decode` or `param.type`.
   * @param fastDecode - When `true`, the decoder should avoid expensive operations (e.g. Frida ↔ native round-trips).
   * @returns The decoded representation of `value`.
   */
  decode: (value: TValue, param: TParam, magicDecode: boolean, fastDecode: boolean) => DecodedValue;
}
