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

export class KeyGenParameterSpecDecoder extends Decoder<Java.Wrapper> {
  keyGenParameterSpec: Java.Wrapper = Java.use("android.security.keystore.KeyGenParameterSpec");

  decode(value: Java.Wrapper) {
    const typedSpec: Java.Wrapper = Java.cast(value, this.keyGenParameterSpec);

    const decodedProperties: Record<string, unknown> = {};

    for (const getter of getters) {
      const fn: Java.MethodDispatcher = typedSpec[getter];
      if (typeof fn?.call !== "function") {
        // Not present on this API level, skip silently
        continue;
      }
      try {
        const raw = fn.call(typedSpec);
        const type: Decodable = {
          type: fn.returnType.className ?? "void",
          settings: this.decodable.settings,
        };
        const propertyDecoder = JavaDecoderResolver.resolveDecoder(type);
        decodedProperties[this.stripPrefix(getter)] = propertyDecoder.decode(raw);
      } catch (e) {
        decodedProperties[this.stripPrefix(getter)] = `Error when decoding : ${e}>`;
      }
    }

    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: decodedProperties,
    };
  }

  stripPrefix(name: string): string {
    if (name.startsWith("get") && name.length > 3) {
      return name[3].toLowerCase() + name.slice(4);
    }
    if (name.startsWith("is") && name.length > 2) {
      return name[2].toLowerCase() + name.slice(3);
    }
    return name;
  }
}
