import { Param } from "../../shared/decoders/decodable";
import { Hook } from "../../shared/hook/hook";

/**
 * Contains all information to hook a native function.
 *
 * @public
 */
export interface NativeHook extends Hook {
  moduleName: string;
  module: Module;
  symbolName: string;
  symbolAddress: NativePointer;
  params?: Param[];
}

export function isNativeHook(hook: Hook): hook is NativeHook {
  return "symbol" in hook;
}
