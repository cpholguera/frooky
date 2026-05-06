import { Param } from "../../shared/decoders/decodableTypes";
import { Hook } from "../../shared/hook/hook";
import { NativeDecodableType } from "../decoders/nativeDecodableTypes";

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
  retType?: NativeDecodableType;
}

export function isNativeHook(hook: Hook): hook is NativeHook {
  return "symbol" in hook;
}
