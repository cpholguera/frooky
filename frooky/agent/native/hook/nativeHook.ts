import type { DecoderSettings } from "../../shared/decoders/decoderSettings";
import type { Hook } from "../../shared/hook/hook";
import type { ParamType } from "../../shared/hook/param";
import type { NativeDecoder } from "../decoders/nativeDecoder";
import type { NativeParam } from "./nativeParam";

/**
 * Name of a native function method.
 *
 * @public
 */
export type SymbolName = string;

export type NativeReturnType = {
  type: ParamType;
  decoder?: typeof NativeDecoder;
  decoderSettings: DecoderSettings;
};

/**
 * Expanded Native method definition with name and optional overloads.
 *
 * @public
 */
export interface NativeFrookyFunctionDefinition {
  symbol: SymbolName;
  returnType?: NativeReturnType;
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
