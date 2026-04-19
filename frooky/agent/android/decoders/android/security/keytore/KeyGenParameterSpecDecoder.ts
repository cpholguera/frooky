import Java from "frida-java-bridge";
import type { Decoder } from "../../../../../shared/decoders/decoder";
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

export const android_security_keystore_KeyGenParameterSpecDecoder: Decoder = {
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
        value[name] = JavaDecoder.decode(raw, { type: fn.returnType.className ?? "void", implementationType: fn.returnType.className ?? "void" });
      } catch (e) {
        value[name] = `Error when decoding : ${e}>`;
      }
    }

    return {
      type: param.implementationType,
      value,
    };
  },
};
