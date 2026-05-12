import Java from "frida-java-bridge";
import { Decoder } from "../../../../../shared/decoders/baseDecoder";
import { Decodable } from "../../../../../shared/decoders/decodable";
import { JavaDecoderResolver } from "../../../javaDecoderResolver";

const getters = [
  "getAlgorithmParameterSpec",
  "getAttestKeyAlias",
  "getAttestationChallenge",
  "getBlockModes",
  "getCertificateNotAfter",
  "getCertificateNotBefore",
  "getCertificateSerialNumber",
  "getCertificateSubject",
  "getDigests",
  "getEncryptionPaddings",
  "getKeySize",
  "getKeyValidityForConsumptionEnd",
  "getKeyValidityForOriginationEnd",
  "getKeyValidityStart",
  "getKeystoreAlias",
  "getMaxUsageCount",
  "getMgf1Digests",
  "getPurposes",
  "getSignaturePaddings",
  "getUserAuthenticationType",
  "getUserAuthenticationValidityDurationSeconds",
  "isDevicePropertiesAttestationIncluded",
  "isDigestsSpecified",
  "isInvalidatedByBiometricEnrollment",
  "isMgf1DigestsSpecified",
  "isRandomizedEncryptionRequired",
  "isStrongBoxBacked",
  "isUnlockedDeviceRequired",
  "isUserAuthenticationRequired",
  "isUserAuthenticationValidWhileOnBody",
  "isUserConfirmationRequired",
  "isUserPresenceRequired",
];

// Cache class wrapper at module scope (avoid re-resolving per call)
let KeyGenParameterSpec: Java.Wrapper | null = null;

function stripPrefix(name: string): string {
  if (name.startsWith("get") && name.length > 3) {
    return name[3].toLowerCase() + name.slice(4);
  }
  if (name.startsWith("is") && name.length > 2) {
    return name[2].toLowerCase() + name.slice(3);
  }
  return name;
}

export class KeyGenParameterSpecDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper) {
    if (!KeyGenParameterSpec) {
      KeyGenParameterSpec = Java.use("android.security.keystore.KeyGenParameterSpec");
    }
    const typedSpec: Java.Wrapper = Java.cast(value, KeyGenParameterSpec);

    const decodedProperties: Record<string, unknown> = {};

    for (const name of getters) {
      const fn: Java.MethodDispatcher = typedSpec[name];
      if (typeof fn?.call !== "function") {
        // Not present on this API level, skip silently
        continue;
      }
      try {
        const raw = fn.call(typedSpec);
        const type: Decodable = {
          type: fn.returnType.className ?? "void",
          decoderSettings: this.settings,
        };
        const propertyDecoder = JavaDecoderResolver.resolveDecoder(type);
        decodedProperties[stripPrefix(name)] = propertyDecoder.decode(raw);
      } catch (e) {
        decodedProperties[stripPrefix(name)] = `Error when decoding : ${e}>`;
      }
    }

    return {
      type: this.type,
      value: decodedProperties,
    };
  }
}
