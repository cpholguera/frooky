import { DEFAULT_DECODE_AT, DEFAULT_DECODER_SETTINGS } from "../config";
import { DecodeAt, Param, RetType } from "../decoders/decodableTypes";
import type { DecoderSettings } from "../decoders/decoderSettings";


type ParamOptions = DecoderSettings & {
  decodeAt: DecodeAt
}

/**
 * Flexible input format for defining a parameter in YAML configuration.
 *
 * Accepts any of the following forms:

 * | Form                  | Type                             | Example                                                          |
 * |-----------------------|----------------------------------|------------------------------------------------------------------|
 * | Type only             | `string`                         | `"java.lang.String"`                                             |
 * | Structured object     | `ParamType`                      | `{ type: "java.lang.String", name: "value", decodeAt: "exit"  }` |
 * | Type + name           | `[string, string]`               | `["java.lang.String", "value"]`                                  |
 * | Type + options        | `[string, ParamOptions]`         | `["java.lang.String", { decodeAt: "exit" }]`                     |
 * | Type + name + options | `[string, string, ParamOptions]` | `["java.lang.String", "value", { decodeAt: "exit" }]`            |
 *
 * @public
 */
export type ParamInput = string | [string, Partial<ParamOptions>] | [string, string] | [Param, string, Partial<ParamOptions>] | Param;

// returns a normalized ParamType from any type of ParamInput
export function normalizeParamType(paramTypeInput: ParamInput): Param {

  // case 1: paramInput is a string
  if (typeof paramTypeInput === "string") {
    return { type: paramTypeInput, decodeAt: DEFAULT_DECODE_AT, settings: DEFAULT_DECODER_SETTINGS };
  }

  // case 2: paramInput is a non-array object
  if (!Array.isArray(paramTypeInput)) {
    return {
      ...paramTypeInput,
      decodeAt: paramTypeInput.decodeAt ?? DEFAULT_DECODE_AT,
      settings: paramTypeInput.settings ?? DEFAULT_DECODER_SETTINGS,
    };
  }

  // case 3: paramInput is an array
  const [first, second, third] = paramTypeInput;

  // case 3.1: [string, string] -> type + name
  if (typeof second === "string") {
    return { type: first as string, name: second, decodeAt: DEFAULT_DECODE_AT, settings: DEFAULT_DECODER_SETTINGS };
  }

  // case 3.2: [string, ParamOptions] -> type + options
  if (third === undefined) {
    const options = second as Partial<ParamOptions>;
    return {
      type: first as string,
      decodeAt: options.decodeAt ?? DEFAULT_DECODE_AT,
      settings: { ...DEFAULT_DECODER_SETTINGS, ...options },
    };
  }

  // case 3.3: [string, string, ParamOptions] -> type + name + options
  const options = third as Partial<ParamOptions>;
  return {
    type: first as string,
    name: second as string,
    decodeAt: options.decodeAt ?? DEFAULT_DECODE_AT,
    settings: { ...DEFAULT_DECODER_SETTINGS, ...options },
  };
}

/**
 * Flexible input format for defining a return type in YAML configuration.
 *
 * Accepts any of the following forms:

 * | Form                    | Type                         | Example                                                                           |
 * |-------------------------|------------------------------|-----------------------------------------------------------------------------------|
 * | Type                    | `string`                     | `{ type: "android.database.sqlite.SQLiteCursor", settings: { maxRecursion: 5 } }` |
 * | Type + decoder settings | `[string, DecoderSettings]`  | `["android.database.sqlite.SQLiteCursor", { maxRecursion: 5 }]`                   |
 *
 * @public
 */
export type ReturnTypeInput = string | [string, Partial<DecoderSettings>];

// returns a normalized ReturnType from any type of ParamInput
export function normalizeReturnType(returnTypeInput: ReturnTypeInput): RetType {

  // case 1: string -> type only
  if (typeof returnTypeInput === "string") {
    return { type: returnTypeInput, settings: DEFAULT_DECODER_SETTINGS };
  }

  // case 2: [string, DecoderSettings] -> type + settings
  const [type, settings] = returnTypeInput;
  return {
    type,
    settings: { ...DEFAULT_DECODER_SETTINGS, ...settings },
  };
}
