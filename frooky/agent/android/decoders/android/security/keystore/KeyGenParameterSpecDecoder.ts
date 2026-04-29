import Java from "frida-java-bridge";
import type { BaseDecoder } from "../../../../../shared/decoders/baseDecoder";
import type { JavaParam } from "../../../../hook/javaParam";
import { JavaDecoder } from "../../../javaDecoder";

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

export const KeyGenParameterSpecDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (spec, param) => {
    if (!KeyGenParameterSpec) {
      KeyGenParameterSpec = Java.use("android.security.keystore.KeyGenParameterSpec");
    }
    const typedSpec: Java.Wrapper = Java.cast(spec, KeyGenParameterSpec);

    const value: Record<string, unknown> = {};

    for (const name of getters) {
      const fn: Java.MethodDispatcher = typedSpec[name];
      if (typeof fn?.call !== "function") {
        // Not present on this API level, skip silently
        continue;
      }
      try {
        const raw = fn.call(typedSpec);
        const type: JavaParam = { type: fn.returnType.className ?? "void", implementationType: fn.returnType.className ?? "void", settings: param.settings, decodeAt: param.decodeAt };
        value[stripPrefix(name)] = JavaDecoder.decode(raw, type);
      } catch (e) {
        value[stripPrefix(name)] = `Error when decoding : ${e}>`;
      }
    }

    return {
      type: param.implementationType ?? param.type,
      value,
    };
  },
};
