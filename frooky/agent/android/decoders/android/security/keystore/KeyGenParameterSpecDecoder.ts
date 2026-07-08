import Java from "frida-java-bridge";
import { Decoder } from "../../../../../shared/decoders/baseDecoder";
import { Decodable } from "../../../../../shared/decoders/decodable";
import { DecodedValue } from "../../../../../shared/decoders/decodedValue";
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

  decode(value: Java.Wrapper): DecodedValue {
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
        const decodable: Decodable = {
          type: fn.returnType.className ?? "void",
          settings: this.decodable.settings,
        };
        const propertyDecoder = JavaDecoderResolver.resolveDecoder(decodable);
        decodedProperties[this.stripPrefix(getter)] = propertyDecoder.decode(raw);
      } catch (e) {
        // When the value is not set and the getter returned null, skip silently
        decodedProperties[this.stripPrefix(getter)] = null;
      }
    }

    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: decodedProperties,
    };
  }

  private stripPrefix(name: string): string {
    if (name.startsWith("get") && name.length > 3) {
      return name[3].toLowerCase() + name.slice(4);
    }
    if (name.startsWith("is") && name.length > 2) {
      return name[2].toLowerCase() + name.slice(3);
    }
    return name;
  }
}
