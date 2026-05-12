import Java from "frida-java-bridge";
import { Decoder } from "../../../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../../../shared/decoders/decodedValue";

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

export class IntentFlagDecoder extends Decoder<Java.Wrapper> {
  decode(value: Java.Wrapper): DecodedValue {
    const bitmask = Number(value) >>> 0;

    const flags = loadIntentFlags();
    const decodedFlags: string[] = [];

    for (const { name, value: flag } of flags) {
      if (flag === 0) continue;
      if ((bitmask & flag) === flag) {
        decodedFlags.push(name);
      }
    }

    return {
      type: "android.content.IntentFlag",
      value: decodedFlags,
    };
  }
}
