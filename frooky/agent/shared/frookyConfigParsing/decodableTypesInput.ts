import { validateAndRepairDecoderSettings } from "../configValidator";
import type { Param, RetType } from "../decoders/decodableTypes";
import type { DecoderSettings } from "../decoders/decoderSettings";
import { DEFAULT_DECODE_AT, DEFAULT_DECODER_SETTINGS } from "../defaultValues";
import type { ParamSettings } from "./settingsInput";

/**
 * Flexible input format for defining a parameter in YAML configuration.
 *
 * | Case | Form                   | Type                              | Example                                                               |
 * |------|------------------------|-----------------------------------|-----------------------------------------------------------------------|
 * | 1    | Type only              | `string`                          | `"java.lang.String"`                                                  |
 * | 2    | Type + name            | `[string, string]`                | `["java.lang.String", "value"]`                                       |
 * | 3    | Type + settings        | `[string, ParamSettings]`         | `["[I", "vector" { decodeAt: "exit", maxRecursion: 5 }]`              |
 * | 4    | Type + name + settings | `[string, string, ParamSettings]` | `["[B", "encryptedOutput", { decodeAt: "exit", magicDecode: false }]` |
 *
 * @public
 */
export type ParamInput = string | [string, string] | [string, ParamSettings] | [string, string, ParamSettings];

export function normalizeParamType(input: ParamInput, decoderSettings?: DecoderSettings): Param {
  const mergedSettings = decoderSettings ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings } : DEFAULT_DECODER_SETTINGS;

  // Case 1: Type only - "java.lang.String"
  if (typeof input === "string") {
    return { type: input, decodeAt: DEFAULT_DECODE_AT, decoderSettings: mergedSettings };
  }
  // Case 2: Type + name - ["java.lang.String", "value"]
  if (input.length === 2 && typeof input[1] === "string") {
    const [type, name] = input;
    return { type, name, decodeAt: DEFAULT_DECODE_AT, decoderSettings: mergedSettings };
  }
  // Case 3: Type + options - ["[I", { decodeAt: "exit", maxRecursion: 5 }]
  if (input.length === 2 && typeof input[1] === "object") {
    const [type, { decodeAt, ...inlineDecoderSettings }] = input as [string, ParamSettings];
    var validatedDecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...inlineDecoderSettings });
    return { type, decodeAt: decodeAt ?? DEFAULT_DECODE_AT, decoderSettings: validatedDecoderSettings };
  }
  // Case 4: Type + name + options - ["[B", "encryptedOutput", { decodeAt: "exit", magicDecode: false }]
  if (input.length === 3) {
    const [type, name, { decodeAt, ...inlineDecoderSettings }] = input as [string, string, ParamSettings];
    var validatedDecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...inlineDecoderSettings });
    return { type, name, decodeAt: decodeAt ?? DEFAULT_DECODE_AT, decoderSettings: validatedDecoderSettings };
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
  const mergedSettings = decoderSettings ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings } : DEFAULT_DECODER_SETTINGS;

  // validate and repair merged settings
  const validatedMergedSettings = validateAndRepairDecoderSettings(mergedSettings);

  // Case 1: Type only - "int"
  if (typeof input === "string") {
    return { type: input, decoderSettings: validatedMergedSettings };
  }
  // Case 2: Type + decoder settings - ["android.database.sqlite.SQLiteCursor", { decodeLimit: 10 }]
  const [type, inlineSettings] = input as [string, Partial<DecoderSettings>];
  return { type, decoderSettings: { ...validatedMergedSettings, ...inlineSettings } };
}
