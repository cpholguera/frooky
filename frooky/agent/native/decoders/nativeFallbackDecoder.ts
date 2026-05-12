import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecodedValue } from "../../shared/decoders/decodedValue";

export class NativeFallbackDecoder extends Decoder<Decodable, NativePointer> {
  public decode(value: NativePointer): DecodedValue {
    return {
      type: this.kind.type,
      value: value.toString(),
    };
  }
}
