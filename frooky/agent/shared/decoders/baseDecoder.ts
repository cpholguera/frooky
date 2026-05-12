import { Decodable } from "./decodable";
import { DecodedValue } from "./decodedValue";

/**
 * Base interface for value decoders.
 *
 * @template TValue - The raw input type to decode.
 * @template TDecodable - The parameter descriptor type, extending {@link Decodable}.
 */
export abstract class Decoder<TKind extends Decodable, TValue> {
  protected kind: TKind;

  constructor(kind: TKind) {
    this.kind = kind;
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
