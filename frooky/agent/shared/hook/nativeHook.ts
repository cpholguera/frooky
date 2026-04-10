import type { Param } from '../hook/parameter';
import type { Hook, ReturnType } from './hook';

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
  params?: Param[];
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
export interface NativeHook extends Hook {
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

// Type guard functions
export function isNativeHook(h: Hook): h is NativeHook {
  return h.type === 'native';
}
