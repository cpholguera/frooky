import { Decoder } from "./baseDecoder";
import { Decodable } from "./decodable";

export interface DecoderResolver<TValue> {
  resolveDecoder(decodable: Decodable): Decoder<TValue>;
}
