import type { NativeFunctionDefinition, NativeHook, SymbolName } from "../hook/nativeHook";
import { normalizeParam, type ParamInput } from "./parameterInput";

export type { SymbolName };

/**
 * Expanded Native function definition with YAML-parsed parameters.
 *
 * @public
 */
export interface NativeFunctionDefinitionInput extends Omit<NativeFunctionDefinition, "params"> {
  params?: ParamInput[];
}

/**
 * Native method selector - either a simple method name or a detailed YAML definition.
 *
 * @public
 */
export type NativeSymbol = SymbolName | NativeFunctionDefinitionInput;

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
  functions: NativeSymbol[];
}

function normalizeFunctionDefinition(input: NativeFunctionDefinitionInput): NativeFunctionDefinition {
  return {
    ...input,
    params: input.params?.map(normalizeParam),
    returnType: input.returnType ? normalizeParam(input.returnType) : undefined
  };
}

function normalizeSymbol(input: NativeSymbol): NativeFunctionDefinition {
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
