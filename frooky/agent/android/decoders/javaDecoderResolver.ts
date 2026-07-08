import type Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecoderResolver } from "../../shared/decoders/decoderResolver";
import { IntentFlagDecoder } from "./android/content/IntentFlagDecoder";
import { IntentUriFlagDecoder } from "./android/content/IntentUriFlagsDecoder";
import { JavaArrayDecoder } from "./javaArrayDecoder";
import { JavaPrimitiveDecoder } from "./javaBasicDecoder";
import { JavaReferenceTypeDecoder } from "./javaReferenceTypeDecoder";

export type DecoderConstructor = { new (decodable: Decodable): Decoder<Java.Wrapper> };

const CUSTOM_CLASS_DECODER_REGISTRY: Record<string, DecoderConstructor> = {
  "android.content.IntentFlagDecoder": IntentFlagDecoder,
  "android.content.IntentUriFlagDecoder": IntentUriFlagDecoder,
};

export const JAVA_PRIMITIVE_TYPES = new Set(["int", "long", "short", "byte", "char", "boolean", "float", "double"]);

/**
 * resolves the decode based on a decodable type
 */
export const JavaDecoderResolver: DecoderResolver<Java.Wrapper> = {
  resolveDecoder(decodable: Decodable): Decoder<Java.Wrapper> {
    if (decodable.settings.customDecoder) {
      // return the custom decoder (if implemented)
      const DecoderClass = CUSTOM_CLASS_DECODER_REGISTRY[decodable.settings.customDecoder];
      return new DecoderClass(decodable);
    } else if (decodable.type.startsWith("[")) {
      // java array decoder
      return new JavaArrayDecoder(decodable);
    } else if (JAVA_PRIMITIVE_TYPES.has(decodable.type) || decodable.type === "void" || decodable.type === "java.lang.String") {
      // other Java primitive types, void and strings (Frida unwraps java.lang.String automatically to JavaScript strings)
      return new JavaPrimitiveDecoder(decodable);
    } else {
      // at this time we don't know the implementation class
      // this decoders resolves the implementation type at first time decode() is called
      return new JavaReferenceTypeDecoder(decodable);
    }
  },
};
