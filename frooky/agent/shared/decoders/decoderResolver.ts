import { Decoder } from "./baseDecoder";
import { Decodable } from "./decodable";

export interface DecoderResolver<TDecodable extends Decodable, TValue> {
  resolveDecoder(decodable: Decodable): Decoder<TDecodable, TValue>;
}
