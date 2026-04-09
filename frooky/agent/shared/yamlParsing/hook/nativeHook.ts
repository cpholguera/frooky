import type { ParamInput } from '../parameter';
import type { BaseHook, ReturnType } from '../../../shared/hook/baseHook';

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
export interface SymbolDefinition {
  symbol: SymbolName;
  returnType?: ReturnType;
  params?: ParamInput[];
}

/**
 * Native method selector — either a simple method name or a detailed definition.
 * 
 * @public
 */
export type NativeSymbol = SymbolDefinition;


/**
 * Native hook configuration.
 *
 * @public
 * @discriminator {type}
 */
export interface NativeHookInput extends BaseHook {
  /**
  * Internally used type guard.
  */
  type: "native"

  /**
   * Fully qualified Native module name.
   */
  module: string;

  /**
   * Symbol to hook on the target module.
   */
  functions: NativeSymbol[];

}

