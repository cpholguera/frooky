import type Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecodedValue } from "../../shared/decoders/decodedValue";

export class JavaLongDecoder extends Decoder<Decodable, Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    return {
      type: this.kind.type,
      value: value.toString(),
    };
  }
}

export class JavaPrimitiveDecoder extends Decoder<Decodable, Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    return {
      type: this.kind.type,
      value: value,
    };
  }
}

export class JavaFallbackDecoder extends Decoder<Decodable, Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    return {
      type: this.kind.type,
      value: value,
    };
  }
}
