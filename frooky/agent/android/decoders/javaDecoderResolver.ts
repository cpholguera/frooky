import type Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecoderResolver } from "../../shared/decoders/decoderResolver";
import { IntentFlagDecoder } from "./android/content/IntentFlagDecoder";
import { KeyGenParameterSpecDecoder } from "./android/security/keystore/KeyGenParameterSpecDecoder";
import { CollectionDecoder } from "./java/util/CollectionDecoder";
import { MapDecoder } from "./java/util/MapDecoder";
import { JavaArrayDecoder } from "./javaArrayDecoder";
import { JavaFallbackDecoder, JavaLongDecoder, JavaPrimitiveDecoder } from "./javaBasicDecoder";
import { JavaDecodable } from "./javaDecodable";

/*
 * This is the registry for non-primitive java decoders.
 */
const javaDecoderRegistry: Record<string, Decoder<JavaDecodable, Java.Wrapper>> = {
  // special java decoders
  JavaArrayDecoder: JavaArrayDecoder,
  JavaLongDecoder: JavaLongDecoder,

  // common java and android decoders
  "java.util.LinkedHashSet": CollectionDecoder,
  "java.util.Arrays$ArrayList": CollectionDecoder,
  "java.util.Collections$SingletonMap": MapDecoder,
  "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,

  // built in custom decoders
  "android.content.IntentFlagDecoder": IntentFlagDecoder,
};

/**
 * resolves the decode based on a decodable type
 */
export const JavaDecoderResolver: DecoderResolver<JavaDecodable, Java.Wrapper> = {
  resolveDecoder(decodable: Decodable): Decoder<JavaDecodable, Java.Wrapper> {
    if (decodable.type.startsWith("[")) {
      // java array decoder
      return javaDecoderRegistry.JavaArrayDecoder;
    } else if (decodable.type === "long") {
      // long decoder
      return javaDecoderRegistry.JavaLongDecoder;
    } else if (typeof input === "object") {
      // query the java decoder registry for decoder for the java types
      // the implementation can be different from the declaration
      // this happens when the declaration is an interface
      // we store the actual implementation type of the object
      param.implementationType = input.$className;
      param.decoder = javaDecoderRegistry[param.implementationType] ?? JavaFallbackDecoder;
    } else {
      // Primitive JS value (already converted by Frida)
      JavaPrimitiveDecoder;
    }
  },
};

// decode(decodable: Decodable): DecoderResolver<Java.Wrapper> {
//   const cachedDecoder = param.decoder;
//   if (cachedDecoder) {
//     // use the cached decoder immediately
//     return cachedDecoder.decode(input, param, settings);
//   } else if (param.type.startsWith("[")) {
//     // java array decoder
//     param.decoder = javaDecoderRegistry.JavaArrayDecoder;
//   } else if (param.type === "long") {
//     // long decoder
//     param.decoder = javaDecoderRegistry.JavaLongDecoder;
//   } else if (typeof input === "object") {
//     // query the java decoder registry for decoder for the java types
//     // the implementation can be different from the declaration
//     // this happens when the declaration is an interface
//     // we store the actual implementation type of the object
//     param.implementationType = input.$className;
//     param.decoder = javaDecoderRegistry[param.implementationType] ?? JavaFallbackDecoder;
//   } else {
//     // Primitive JS value (already converted by Frida)
//     param.decoder = JavaPrimitiveDecoder;
//   }
//   return param.decoder.decode(input, param, settings);
// },
