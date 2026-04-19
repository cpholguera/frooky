import Java from "frida-java-bridge";
import type { Decoder } from "../../../../shared/decoders/decoder";

// Cache so we only reflect once
let FLAG_CACHE: Array<{ name: string; value: number }> | null = null;

function loadIntentFlags(): Array<{ name: string; value: number }> {
  if (FLAG_CACHE) return FLAG_CACHE;

  const IntentClass = Java.use("android.content.Intent");
  const clazz = IntentClass.class;
  const fields = clazz.getDeclaredFields();

  const Modifier = Java.use("java.lang.reflect.Modifier");

  const flags: Array<{ name: string; value: number }> = [];

  for (let i = 0; i < fields.length; i++) {
    const f = fields[i];
    const name: string = f.getName();
    const mods: number = f.getModifiers();

    const isPublic = Modifier.isPublic(mods);
    const isStatic = Modifier.isStatic(mods);
    const isFinal = Modifier.isFinal(mods);
    const isInt = f.getType().getName() === "int";

    if (isPublic && isStatic && isFinal && isInt && name.startsWith("FLAG_")) {
      f.setAccessible(true);
      // getInt(null) for static fields
      const value: number = f.getInt(null);
      flags.push({ name, value: value >>> 0 });
    }
  }

  FLAG_CACHE = flags;
  return flags;
}

export const android_content_IntentFlagDecoder: Decoder = {
  decode: (input) => {
    console.log(typeof input);
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
