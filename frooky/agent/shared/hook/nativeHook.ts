import type { Param } from "../hook/parameter";
import type { Hook } from "./hook";

/**
 * Name of a native function method.
 *
 * @public
 */
export type SymbolName = string;

/**
 * Expanded Native method definition with name and optional overloads.
 *
 * @public
 */
export interface NativeFrookyFunctionDefinition {
  symbol: SymbolName;
  returnType?: Param;
  params?: Param[];
}

/**
 * Native method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type NativeFrookyFunction = NativeFrookyFunctionDefinition;

/**
 * Native hook configuration.
 *
 * @public
 * @discriminator {type}
 */
export interface NativeHook extends Hook {
  /**
   * Fully qualified Native module name.
   */
  module: string;

  /**
   * Symbol to hook on the target module.
   */
  functions: NativeFrookyFunction[];
}

export function isNativeHook(h: Hook): h is NativeHook {
  return "functions" in h;
}
