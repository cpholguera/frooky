import { DEFAULT_DECODE_AT, DEFAULT_DECODER_SETTINGS } from "../config";
import { DecodeAt, Param, RetType } from "../decoders/decodableTypes";
import type { DecoderSettings } from "../decoders/decoderSettings";
import { validateAndNormalizeDecoderSettings } from "../validator/configValidator";


type ParamSettings = Partial<DecoderSettings> & {
  decodeAt?: DecodeAt
}

/**
 * Flexible input format for defining a parameter in YAML configuration.
 *
 * | Case | Form                  | Type                              | Example                                                               |
 * |------|-----------------------|-----------------------------------|-----------------------------------------------------------------------|
 * | 1    | Type only             | `string`                          | `"java.lang.String"`                                                  |
 * | 2    | Type + name           | `[string, string]`                | `["java.lang.String", "value"]`                                       |
 * | 3    | Type + options        | `[string, ParamSettings]`         | `["[I", "vector" { decodeAt: "exit", maxRecursion: 5 }]`              |
 * | 4    | Type + name + options | `[string, string, ParamSettings]` | `["[B", "encryptedOutput", { decodeAt: "exit", magicDecode: false }]` |
 *
 * @public
 */
export type ParamInput =
  | string
  | [string, string]
  | [string, ParamSettings]
  | [string, string, ParamSettings];

export function normalizeParamType(input: ParamInput, decoderSettings?: DecoderSettings): Param {
  const mergedSettings = decoderSettings
    ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings }
    : DEFAULT_DECODER_SETTINGS;

  // Case 1: Type only - "java.lang.String"
  if (typeof input === "string") {
    return { type: input, decodeAt: DEFAULT_DECODE_AT, settings: mergedSettings };
  }
  // Case 2: Type + name - ["java.lang.String", "value"]
  if (input.length === 2 && typeof input[1] === "string") {
    const [type, name] = input;
    return { type, name, decodeAt: DEFAULT_DECODE_AT, settings: mergedSettings };
  }
  // Case 3: Type + options - ["[I", { decodeAt: "exit", maxRecursion: 5 }]
  if (input.length === 2 && typeof input[1] === "object") {
    const [type, { decodeAt, ...inlineSettings }] = input as [string, ParamSettings];
    return { type, decodeAt: decodeAt ?? DEFAULT_DECODE_AT, settings: { ...mergedSettings, ...inlineSettings } };
  }
  // Case 4: Type + name + options - ["[B", "encryptedOutput", { decodeAt: "exit", magicDecode: false }]
  if (input.length === 3) {
    const [type, name, { decodeAt, ...inlineSettings }] = input as [string, string, ParamSettings];
    return { type, name, decodeAt: decodeAt ?? DEFAULT_DECODE_AT, settings: { ...mergedSettings, ...inlineSettings } };
  }
  throw new Error(`Unrecognized ParamInput format: ${JSON.stringify(input)}`);
}


/**
 * Flexible input format for defining a return type in YAML configuration.
 *
 * | Case | Form                    | Type                        | Example                                                          |
 * |------|-------------------------|-----------------------------|------------------------------------------------------------------|
 * | 1    | Type only               | `string`                    | `"int"`                                                          |
 * | 2    | Type + decoder settings | `[string, DecoderSettings]` | `["android.database.sqlite.SQLiteCursor", { decodeLimit: 10 }]`  |
 *
 * @public
 */
export type RetTypeInput = string | [string, Partial<DecoderSettings>];

export function normalizeReturnType(input: RetTypeInput, decoderSettings?: DecoderSettings): RetType {
  const mergedSettings = decoderSettings
    ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings }
    : DEFAULT_DECODER_SETTINGS;

  // Case 1: Type only - "int"
  if (typeof input === "string") {
    return { type: input, settings: mergedSettings };
  }
  // Case 2: Type + decoder settings - ["android.database.sqlite.SQLiteCursor", { decodeLimit: 10 }]
  const [type, inlineSettings] = input as [string, Partial<DecoderSettings>];
  return { type, settings: { ...mergedSettings, ...inlineSettings } };
}
