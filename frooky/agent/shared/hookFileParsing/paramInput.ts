import { DEFAULT_DECODER_SETTINGS } from "../config";
import type { DecoderSettings } from "../decoders/decoderSettings";
import type { Param, ParamName, ParamType } from "../hook/param";

/**
 * Flexible input format for defining a parameter in YAML configuration.
 *
 * Accepts any of the following forms:
 *
 * | Form                  | Type                                   | Example                                                                      |
 * |-----------------------|----------------------------------------|------------------------------------------------------------------------------|
 * | Type only             | `ParamType`                            | `"java.lang.String"`                                                         |
 * | Type + options        | `[ParamType, ParamOptions]`            | `["java.lang.String", { decodeAt: "exit" }]`                                 |
 * | Type + name           | `[ParamType, ParamName]`               | `["java.lang.String", "value"]`                                              |
 * | Type + name + options | `[ParamType, ParamName, ParamOptions]` | `["java.lang.String", "value", { decodeAt: "exit" }]`                        |
 * | Structured object     | `Param`                                | `{ type: "java.lang.String", name: "value", options: { decodeAt: "exit" } }` |
 *
 * @public
 */
export type ParamInput = ParamType | [ParamType, Partial<DecoderSettings>] | [ParamType, ParamName] | [ParamType, ParamName, Partial<DecoderSettings>] | Param;

// returns a normalized ParamDefinition from any type of ParamInput
export function normalizeParam(param: ParamInput): Param {
  if (typeof param === "string") {
    return { type: param, decoderSettings: DEFAULT_DECODER_SETTINGS };
  }

  // Check array before plain object, since arrays are also objects
  if (Array.isArray(param)) {
    const [paramType, paramNameOrDecoderSettings, decoderSettings] = param;

    if (param.length === 3) {
      return {
        type: paramType,
        name: paramNameOrDecoderSettings as string,
        decoderSettings: decoderSettings as DecoderSettings,
      };
    }

    if (typeof paramNameOrDecoderSettings === "object") {
      return { type: paramType, decoderSettings: paramNameOrDecoderSettings as DecoderSettings };
    }

    return { type: paramType, name: paramNameOrDecoderSettings, decoderSettings: DEFAULT_DECODER_SETTINGS };
  }

  return param as Param;
}
