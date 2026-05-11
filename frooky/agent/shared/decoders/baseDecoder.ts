import { Decodable } from "./decodable";
import { DecodedValue } from "./decodedValue";

/**
 * Base interface for value decoders.
 *
 * @template TValue - The raw input type to decode.
 * @template TParam - The parameter descriptor type, extending {@link Param}.
 */
export abstract class Decoder<TValue> {
  protected decodable: Decodable;

  constructor(decodable: Decodable) {
    this.decodable = decodable;
  }

  /**
   * Decodes a raw value into a {@link DecodedValue}.
   *
   * @param value - The raw value to decode.
   * @param ctx - Additional context such as the type, decoder settings or additional arguments
   * @returns The decoded representation of `value`.
   */
  public abstract decode(value: TValue): DecodedValue;
}
