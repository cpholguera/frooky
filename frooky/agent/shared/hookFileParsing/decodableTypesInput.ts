import { DEFAULT_DECODE_AT, DEFAULT_DECODER_SETTINGS } from "../config";
import { DecodeAt, Param, RetType } from "../decoders/decodableTypes";
import type { DecoderSettings } from "../decoders/decoderSettings";
import { validateAndNormalizeDecoderSettings } from "../validator/configValidator";


type ParamOptions = Partial<DecoderSettings> & {
  decodeAt?: DecodeAt
}

/**
 * Flexible input format for defining a parameter in YAML configuration.
 *
 * | Case | Form                  | Type                             | Example                                                           |
 * |------|-----------------------|----------------------------------|-------------------------------------------------------------------|
 * | 1    | Type only             | `string`                         | `"java.lang.String"`                                              |
 * | 2    | Structured object     | `Param`                          | `{ type: "java.lang.String", name: "value", decodeAt: "exit" }`   |
 * | 3    | Type + name           | `[string, string]`               | `["java.lang.String", "value"]`                                   |
 * | 4    | Type + options        | `[string, ParamOptions]`         | `["java.lang.String", { decodeAt: "exit" }]`                      |
 * | 5    | Type + name + options | `[string, string, ParamOptions]` | `["java.lang.String", "value", { decodeAt: "exit" }]`             |
 *
 * @public
 */
export type ParamInput =
  | string
  | Param
  | [string, string]
  | [string, ParamOptions]
  | [string, string, ParamOptions];

type ParamInputCase = "string" | "object" | "type+name" | "type+options" | "type+name+options";

function resolveParamCase(input: ParamInput): ParamInputCase {
  if (typeof input === "string")                                                     return "string";
  if (!Array.isArray(input))                                                         return "object";
  if (input.length === 2 && typeof input[1] === "string")                            return "type+name";
  if (input.length === 3)                                                            return "type+name+options";
  if (input.length === 2 && typeof input[1] === "object")                            return "type+options";
  throw new Error(`Unrecognized ParamInput format: ${JSON.stringify(input)}`);
}

export function normalizeParamType(input: ParamInput, decoderSettings?: DecoderSettings): Param {
  const baseSettings = decoderSettings
    ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings }
    : DEFAULT_DECODER_SETTINGS;

  switch (resolveParamCase(input)) {
    case "string": {
      return { type: input as string, decodeAt: DEFAULT_DECODE_AT, settings: baseSettings };
    }

    case "object": {
      const param = input as Param;
      validateAndNormalizeDecoderSettings(param.settings);
      return { ...param, decodeAt: param.decodeAt ?? DEFAULT_DECODE_AT, settings: baseSettings };
    }

    case "type+name": {
      const [type, name] = input as [string, string];
      return { type, name, decodeAt: DEFAULT_DECODE_AT, settings: baseSettings };
    }

    case "type+options": {
      const [type, options] = input as [string, ParamOptions];
      const { decodeAt, ...inlineSettings } = options;
      return { type, decodeAt: decodeAt ?? DEFAULT_DECODE_AT, settings: { ...baseSettings, ...inlineSettings } };
    }

    case "type+name+options": {
      const [type, name, options] = input as [string, string, ParamOptions];
      const { decodeAt, ...inlineSettings } = options;
      return { type, name, decodeAt: decodeAt ?? DEFAULT_DECODE_AT, settings: { ...baseSettings, ...inlineSettings } };
    }
  }
}



/**
 * Flexible input format for defining a return type in YAML configuration.
 *
 * | Case | Form                    | Type                        | Example                                                                            |
 * |------|-------------------------|-----------------------------|------------------------------------------------------------------------------------|
 * | 1    | Type only               | `string`                    | `"android.database.sqlite.SQLiteCursor"`                                           |
 * | 2    | Type + decoder settings | `[string, DecoderSettings]` | `["android.database.sqlite.SQLiteCursor", { maxRecursion: 5 }]`                    |
 *
 * @public
 */
export type RetTypeInput = string | [string, Partial<DecoderSettings>];

type RetTypeInputCase = "string" | "type+settings";

function resolveRetTypeCase(input: RetTypeInput): RetTypeInputCase {
  if (typeof input === "string") return "string";
  if (Array.isArray(input))     return "type+settings";
  throw new Error(`Unrecognized RetTypeInput format: ${JSON.stringify(input)}`);
}

export function normalizeReturnType(input: RetTypeInput, decoderSettings?: DecoderSettings): RetType {
  const baseSettings = decoderSettings
    ? { ...DEFAULT_DECODER_SETTINGS, ...decoderSettings }
    : DEFAULT_DECODER_SETTINGS;

  switch (resolveRetTypeCase(input)) {
    case "string": {
      return { type: input as string, settings: baseSettings };
    }

    case "type+settings": {
      const [type, inlineSettings] = input as [string, Partial<DecoderSettings>];
      return { type, settings: { ...baseSettings, ...inlineSettings } };
    }
  }
}