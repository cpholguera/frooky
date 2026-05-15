import type Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecoderResolver } from "../../shared/decoders/decoderResolver";
import { JavaArrayDecoder } from "./javaArrayDecoder";
import { JavaPrimitiveDecoder } from "./javaBasicDecoder";
import { JavaClassDecoder } from "./javaClassDecoder";

export const JAVA_PRIMITIVE_TYPES = new Set(["int", "long", "short", "byte", "char", "boolean", "float", "double"]);

/**
 * resolves the decode based on a decodable type
 */
export const JavaDecoderResolver: DecoderResolver<Java.Wrapper> = {
  resolveDecoder(decodable: Decodable): Decoder<Java.Wrapper> {
    if (decodable.settings.customDecoder) {
      // return the custom decoder (if implemented)
      return new JavaClassDecoder(decodable);
    } else if (decodable.type.startsWith("[")) {
      // java array decoder
      return new JavaArrayDecoder(decodable);
    } else if (JAVA_PRIMITIVE_TYPES.has(decodable.type) || decodable.type === "void") {
      // other Java primitive types and void
      return new JavaPrimitiveDecoder(decodable);
    }
    // at this time we don't know the implementation class
    // this decoders resolves the implementation type at first time decode() is called
    return new JavaClassDecoder(decodable);
  },
};
