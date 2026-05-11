import { Decoder } from "./baseDecoder";
import { Decodable } from "./decodable";

export interface DecoderResolver<TDecoder> {
  resolveDecoder(decodable: Decodable): Decoder<TDecoder>;
}
