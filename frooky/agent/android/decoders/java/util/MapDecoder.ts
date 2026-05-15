import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";
import { IterableDecoder } from "../lang/IterableDecoder";

export class MapDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const valueCollection = value.values();
    const iterableDecoder = new IterableDecoder(this.decodable);
    const decodedValues = iterableDecoder.decode(valueCollection);

    const keySet = value.keySet();
    const decodedKeySet = iterableDecoder.decode(keySet);

    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: [
        { ...decodedKeySet, name: "key" },
        { ...decodedValues, name: "value" },
      ],
    };
  }
}
