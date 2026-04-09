import { Param, ParamName, ParamOptions, ParamType } from "../parameter";

/**
 * Extended parameter type for YAML input parsing.
 * 
 * The following examples all describe the same parameter:
 *
 * 1. As a simple type name.
 * 2. As a tuple of [type, options].
 * 3. As a tuple of [type, name, options].
 * 4. As a structured object with type, name, and options.
 *
 * @example "java.lang.String"
 * @example ["java.lang.String", { decodeAt: "exit" }]
 * @example ["java.lang.String", "value", { decodeAt: "exit" }]
 * @example { type: "java.lang.String", name: "value", options: { decodeAt: "exit" } }
 *
 * @public
 */
export type ParamInput =
  | Param
  | ParamType
  | [ParamType, ParamName]
  | [ParamType, ParamOptions]
  | [ParamType, ParamName, ParamOptions];
