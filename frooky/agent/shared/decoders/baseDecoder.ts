import type { DecodedValue } from "./decodedValue";

/**
 * Base interface for value decoders.
 *
 * @template TValue - The raw input type to decode.
 * @template TParam - The parameter descriptor type, extending {@link Param}.
 */
export interface BaseDecoder<TValue, TDecodableType> {
  /**
   * Decodes a raw value into a {@link DecodedValue}.
   *
   * @param value - The raw value to decode.
   * @param settings - Settings used when decoding the value.
   * @param args - Arguments passed to the decoder.
   * @returns The decoded representation of `value`.
   */
  decode: (value: TValue, decodableType: TDecodableType, args?: any[]) => DecodedValue;
}
