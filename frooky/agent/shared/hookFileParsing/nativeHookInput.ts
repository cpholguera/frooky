import type { NativeFrookyFunctionDefinition, NativeHook, SymbolName } from "../../native/hook/nativeHook";
import type { Hook } from "../hook/hook";
import { normalizeParam, type ParamInput } from "./parameterInput";

export type { SymbolName };

/**
 * Expanded Native function definition with YAML-parsed parameters.
 *
 * @public
 */
export interface NativeFunctionDefinitionInput extends Omit<NativeFrookyFunctionDefinition, "params"> {
  params?: ParamInput[];
}

/**
 * Native method selector - either a simple method name or a detailed YAML definition.
 *
 * @public
 */
export type NativeFrookyFunction = SymbolName | NativeFunctionDefinitionInput;

/**
 * Native hook configuration for YAML parsing.
 * Extends {@link NativeHook} with a looser `functions` type that accepts
 * both plain symbol names and detailed definitions.
 *
 * @public
 * @discriminator {type}
 */
export interface NativeHookInput extends Omit<NativeHook, "functions"> {
  type: "native";
  functions: NativeFrookyFunction[];
}

// Type guard function
export function isNativeHook(h: Hook): h is NativeHook {
  return "functions" in h;
}

function normalizeFunctionDefinition(input: NativeFunctionDefinitionInput): NativeFrookyFunctionDefinition {
  return {
    ...input,
    params: input.params?.map(normalizeParam),
    returnType: input.returnType ? normalizeParam(input.returnType) : undefined,
  };
}

function normalizeSymbol(input: NativeFrookyFunction): NativeFrookyFunctionDefinition {
  if (typeof input === "string") {
    return { symbol: input };
  }
  return normalizeFunctionDefinition(input);
}

export function normalizeNativeHook(input: NativeHookInput): NativeHook {
  return {
    ...input,
    functions: input.functions.map(normalizeSymbol),
  };
}
