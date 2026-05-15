import type Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";

export class JavaPrimitiveDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: this.decodable.type === "long" ? value.toString() : value,
    };
  }
}

export class JavaFallbackDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: value.toString(),
    };
  }
}
