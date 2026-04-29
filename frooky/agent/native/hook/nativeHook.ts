import type { RetType } from "../../shared/decoders/decodableTypes";
import type { DecoderSettings } from "../../shared/decoders/decoderSettings";
import type { Hook } from "../../shared/hook/hook";
import type { NativeParam } from "../decoders/nativeDecodableTypes";

/**
 * Expanded Native method definition with name and optional overloads.
 *
 * @public
 */
export interface NativeFrookyFunction {
  symbol: string;
  params?: NativeParam[];
  retType?: RetType;
  decoderSettings: DecoderSettings;
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
