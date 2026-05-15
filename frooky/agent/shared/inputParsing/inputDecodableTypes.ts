import { validateAndRepairDecoderSettings } from "../configValidator";
import { Param, Decodable as RetType } from "../decoders/decodable";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_DECODE_AT } from "../defaultValues";
import { DecoderSettings } from "../frookySettings";
import { InputParamSettings } from "./inputSettings";

/**
 * Flexible input format for defining a parameter in YAML configuration.
 *
 * | Case | Form                   | Type                                    | Example                                                               |
 * |------|------------------------|----------------------------------------|-----------------------------------------------------------------------|
 * | 1    | Type only              | `string`                               | `"java.lang.String"`                                                  |
 * | 2    | Type + name            | `[string, string]`                     | `["java.lang.String", "value"]`                                       |
 * | 3    | Type + settings        | `[string, InputParamSettings]`         | `["[I", "vector" { direction: "exit", maxRecursion: 5 }]`              |
 * | 4    | Type + name + settings | `[string, string, InputParamSettings]` | `["[B", "encryptedOutput", { direction: "exit", magicDecode: false }]` |
 * | 5    | Normalized object      | `Param`                                | `{ type: int, name: age, direction: "exit", settings: { ... }}`        |
 *
 * Note: Internally we only use the normalized version. The other forms are used to add flexibility for the frooky input file.
 *
 * @public
 */
export type InputParam = string | [string, string] | [string, InputParamSettings] | [string, string, InputParamSettings] | Param;

export function normalizeInputParam(input: InputParam, decoderSettings?: DecoderSettings): Param {
  const mergedSettings = decoderSettings ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings } : DEFAULT_DECODER_SETTINGS;

  // Case 1: Type only - "java.lang.String"
  if (typeof input === "string") {
    return { type: input, direction: DEFAULT_DECODE_AT, settings: mergedSettings };
  } else if (Array.isArray(input)) {
    // Case 2: Type + name - ["java.lang.String", "value"]
    if (input.length === 2 && typeof input[1] === "string") {
      const [type, name] = input;
      return { type, direction: DEFAULT_DECODE_AT, settings: mergedSettings, name };
    }
    // Case 3: Type + options - ["[I", { direction: "exit", maxRecursion: 5 }]
    if (input.length === 2 && typeof input[1] === "object") {
      const [type, { direction, ...inlineDecoderSettings }] = input as [string, InputParamSettings];
      const validatedDecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...inlineDecoderSettings });
      return { type, direction: direction ?? DEFAULT_DECODE_AT, settings: validatedDecoderSettings };
    }
    // Case 4: Type + name + options - ["[B", "encryptedOutput", { direction: "exit", magicDecode: false }]
    if (input.length === 3) {
      const [type, name, { direction, ...inlineDecoderSettings }] = input as [string, string, InputParamSettings];
      const validatedDecoderSettings = validateAndRepairDecoderSettings({ ...DEFAULT_DECODER_SETTINGS, ...inlineDecoderSettings });
      return { type, direction: direction ?? DEFAULT_DECODE_AT, settings: validatedDecoderSettings, name };
    }
  } else if (typeof input === "object") {
    // Case 5: Normalized object
    return input;
  }
  throw new Error(`Unrecognized InputParam format: ${JSON.stringify(input)}`);
}

/**
 * Flexible input format for defining a return type in YAML configuration.
 *
 * | Case | Form                    | Type                        | Example                                                          |
 * |------|-------------------------|-----------------------------|------------------------------------------------------------------|
 * | 1    | Type only               | `string`                    | `"int"`                                                          |
 * | 2    | Type + decoder settings | `[string, DecoderSettings]` | `["android.database.sqlite.SQLiteCursor", { decodeLimit: 10 }]`  |
 * | 3    | Normalized object       | `DecodableType`             | `{ type: int, decoderSettings: { magicDecode: false }}`          |
 *
 *  Note: Internally we only use the normalized version. The other forms are used to add flexibility for the frooky input file.
 *
 * @public
 */
export type InputRetType = string | [string, Partial<DecoderSettings>] | RetType;

export function normalizeInputRetType(input: InputRetType, decoderSettings?: DecoderSettings): RetType {
  const mergedSettings = decoderSettings ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings } : DEFAULT_DECODER_SETTINGS;

  // validate and repair merged settings
  const validatedMergedSettings = validateAndRepairDecoderSettings(mergedSettings);

  // Case 1: Type only - "int"
  if (typeof input === "string") {
    return { type: input, settings: validatedMergedSettings };
  } else if (Array.isArray(input)) {
    // Case 2: Type + decoder settings - ["android.database.sqlite.SQLiteCursor", { decodeLimit: 10 }]
    const [type, inlineSettings] = input as [string, Partial<DecoderSettings>];
    return { type, settings: { ...validatedMergedSettings, ...inlineSettings } };
  } else if (typeof input === "object") {
    // Case 3: Normalized object
    return input;
  }
  throw new Error(`Unrecognized InputRetType format: ${JSON.stringify(input)}`);
}
