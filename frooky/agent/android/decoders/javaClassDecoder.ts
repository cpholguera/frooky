import Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DecoderSettings } from "../../shared/frookySettings";
import { IntentFlagDecoder } from "./android/content/IntentFlagDecoder";
import { KeyGenParameterSpecDecoder } from "./android/security/keystore/KeyGenParameterSpecDecoder";

import { IterableDecoder } from "./java/lang/IterableDecoder";
import { JavaFallbackDecoder } from "./javaBasicDecoder";

type DecoderConstructor = { new (type: string, settings: DecoderSettings): Decoder<Java.Wrapper> };

const javaClassDecoderRegistry: Record<string, DecoderConstructor> = {
  // common java and android decoders
  "java.util.LinkedHashSet": IterableDecoder,
  "java.util.Arrays$ArrayList": IterableDecoder,
  // "java.util.Collections$SingletonMap": MapDecoder,
  "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,

  // built in custom decoders
  "android.content.IntentFlagDecoder": IntentFlagDecoder,
};

export class JavaClassDecoder extends Decoder<Java.Wrapper> {
  implementationDecoder: Decoder<Java.Wrapper> | undefined;

  decode(value: Java.Wrapper): DecodedValue {
    if (!this.implementationDecoder) {
      // Try to find a decoder in the registry with fall back to JavaFallbackDecoder
      const DecoderClass = javaClassDecoderRegistry[value.$className];
      this.implementationDecoder = DecoderClass
        ? new DecoderClass(value.$className, this.settings)
        : new JavaFallbackDecoder(this.type, this.settings);
    }

    return {
      type: this.type,
      value: this.implementationDecoder.decode(value),
    };
  }
}
