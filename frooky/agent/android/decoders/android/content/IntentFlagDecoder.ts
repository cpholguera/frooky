import Java from "frida-java-bridge";
import type { Decoder } from "../../../../shared/decoders/decoder";

// Cache so we only reflect once
let FLAG_CACHE: Array<{ name: string; value: number }> | null = null;

function loadIntentFlags() {
  if (FLAG_CACHE) return FLAG_CACHE;
  const IntentClass = Java.use("android.content.Intent");
  const fields = IntentClass.class.getFields(); // public only
  const flags: Array<{ name: string; value: number }> = [];
  for (let i = 0; i < fields.length; i++) {
    const f = fields[i];
    const name: string = f.getName();
    if (!name.startsWith("FLAG_")) continue;
    if (f.getType().getName() !== "int") continue;
    flags.push({ name, value: f.getInt(null) >>> 0 });
  }
  FLAG_CACHE = flags;
  return flags;
}

export const IntentFlagDecoder: Decoder = {
  decode: (input) => {
    const bitmask = Number(input) >>> 0;

    const flags = loadIntentFlags();
    const value: string[] = [];

    for (const { name, value: flag } of flags) {
      if (flag === 0) continue;
      if ((bitmask & flag) === flag) {
        value.push(name);
      }
    }

    return {
      type: "android.content.IntentFlag",
      value,
    };
  },
};
