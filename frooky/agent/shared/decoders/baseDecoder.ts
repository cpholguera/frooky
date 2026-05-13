import { DecoderSettings } from "../frookySettings";
import { DecodedValue } from "./decodedValue";

export type DecoderArgs<TValue> = {
  arg: TValue;
  decoder: Decoder<TValue>;
  name: string;
};

/**
 * Base interface for value decoders.
 *
 * @template TValue - The raw input type to decode.
 */
export abstract class Decoder<TValue> {
  protected type: string;
  protected settings: DecoderSettings;

  constructor(type: string, settings: DecoderSettings) {
    this.type = type;
    this.settings = settings;
  }

  /**
   * Decodes a raw value into a {@link DecodedValue}.
   *
   * @param value - The raw value to decode.
   * @param args - Arguments passed to the decoder
   * @returns The decoded representation of `value`.
   */
  public abstract decode(value: TValue, args?: DecoderArgs<TValue>[]): DecodedValue;
}
