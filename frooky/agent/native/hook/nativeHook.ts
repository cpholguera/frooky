import { RetType } from "../../shared/decoders/decodableTypes";
import type { Hook } from "../../shared/hook/hook";
import { NativeParam } from "../decoders/nativeDecodableTypes";


/**
 * Expanded Native method definition with name and optional overloads.
 *
 * @public
 */
export interface NativeFrookyFunction {
  symbol: string;
  returnType?: RetType;
  params?: NativeParam[];
}

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
