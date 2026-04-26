import type { Hook } from "../../shared/hook/hook";
import { NativeParam } from "./nativeParam";

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
  returnType?: NativeParam;
  params?: NativeParam[];
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

