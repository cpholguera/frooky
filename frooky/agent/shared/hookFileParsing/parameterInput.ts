import type { Param, ParamName, ParamOptions, ParamType } from "../hook/param";

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
export type ParamInput = ParamType | [ParamType, ParamOptions] | [ParamType, ParamName] | [ParamType, ParamName, ParamOptions] | Param;

// returns a normalized ParamDefinition from any type of ParamInput
export function normalizeParam(input: ParamInput): Param {
  if (typeof input === "string") {
    return { type: input };
  }

  // Check array before plain object, since arrays are also objects
  if (Array.isArray(input)) {
    const [paramType, paramNameOrParamOptions, paramOptions] = input;

    if (input.length === 3) {
      return {
        type: paramType,
        name: paramNameOrParamOptions as string,
        options: paramOptions as ParamOptions,
      };
    }

    if (typeof paramNameOrParamOptions === "object") {
      return { type: paramType, options: paramNameOrParamOptions };
    }

    return { type: paramType, name: paramNameOrParamOptions };
  }

  return input as Param;
}
