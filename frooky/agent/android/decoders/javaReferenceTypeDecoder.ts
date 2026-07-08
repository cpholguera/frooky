import Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { ClipDataDecoder } from "./android/content/clipData/ClipDataDecoder";
import { ClipDataItemDecoder } from "./android/content/clipData/ClipDataItemDecoder";
import { ContentValuesDecoder } from "./android/content/ContentValuesDecoder";
import { IntentDecoder } from "./android/content/IntentDecoder";
import { BundleDecoder } from "./android/os/BundleDecoder";
import { KeyGenParameterSpecDecoder } from "./android/security/keystore/KeyGenParameterSpecDecoder";
import { IterableDecoder } from "./java/lang/IterableDecoder";
import { MapDecoder } from "./java/util/MapDecoder";
import { JavaFallbackDecoder } from "./javaBasicDecoder";
import { DecoderConstructor } from "./javaDecoderResolver";

const CLASS_DECODER_REGISTRY: Record<string, DecoderConstructor> = {
  "android.content.Intent": IntentDecoder,
  "android.content.ClipData": ClipDataDecoder,
  "android.content.ClipData$Item": ClipDataItemDecoder,
  "android.os.Bundle": BundleDecoder,
  "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,
  "android.content.ContentValues": ContentValuesDecoder,
};

const INTERFACE_DECODER_REGISTRY: Record<string, DecoderConstructor> = {
  "java.util.Map": MapDecoder,
  "java.lang.Iterable": IterableDecoder,
};

const _decoderCache = new Map<string, DecoderConstructor>();

function collectInterfaces(javaClass: Java.Wrapper): Set<string> {
  const result = new Set<string>();

  while (javaClass !== null) {
    try {
      const ifaces: Java.Wrapper[] = javaClass.getInterfaces();
      for (const iface of ifaces) {
        const name: string = iface.getName();
        if (!result.has(name)) {
          result.add(name);
          for (const n of collectInterfaces(iface)) result.add(n);
        }
      }
      javaClass = javaClass.getSuperclass();
    } catch (e) {
      frooky.log.warn(`Error when resolving interfaces for class ${javaClass.$className}: ${e}`);
      break;
    }
  }

  return result;
}

function resolveInterfaceDecoderClass(value: Java.Wrapper): DecoderConstructor | null {
  const cachedDecoder = _decoderCache.get(value.$className);
  if (cachedDecoder !== undefined) return cachedDecoder;

  const interfaces = collectInterfaces(value.class);
  for (const iface of interfaces) {
    const interfaceDecoder = INTERFACE_DECODER_REGISTRY[iface];
    if (interfaceDecoder) {
      _decoderCache.set(value.$className, interfaceDecoder);
      return interfaceDecoder;
    }
  }

  return null;
}

export class JavaReferenceTypeDecoder extends Decoder<Java.Wrapper> {
  private decoder: Decoder<Java.Wrapper> | undefined;

  decode(value: Java.Wrapper): DecodedValue {
    if (!this.decoder) {
      frooky.log.debug(`Resolving decoder for declared type: ${this.decodable.type}`);

      let decoderConstructor: DecoderConstructor;

      // 1. class decoder for the runtime class exists
      if (CLASS_DECODER_REGISTRY[value.$className]) {
        decoderConstructor = CLASS_DECODER_REGISTRY[value.$className];
        _decoderCache.set(value.$className, decoderConstructor);
      }
      // 2. interface decoder for declared interface type exits
      else if (INTERFACE_DECODER_REGISTRY[this.decodable.type]) {
        decoderConstructor = INTERFACE_DECODER_REGISTRY[this.decodable.type];
        _decoderCache.set(this.decodable.type, decoderConstructor);
      }
      // 3. resolve the interfaces and use a decoder if implemented or fall back to the JavaFallbackDecoder
      else {
        decoderConstructor = resolveInterfaceDecoderClass(value) ?? JavaFallbackDecoder;
      }
      this.decoder = new decoderConstructor({
        type: value.$className,
        name: this.decodable.name,
        settings: this.decodable.settings,
      });
    }

    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: this.decoder.decode(value),
    };
  }
}
