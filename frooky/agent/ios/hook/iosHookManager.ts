import { HookManager } from "../../shared/hook/hookManager";
import { InputObjcHookNormalized } from "../../shared/inputParsing/inputIosHookGroup";
import { PlatformStackTrace } from "../../shared/platformStackTrace";
import { ObjcDecoderResolver } from "../decoders/objcDecoderResolver";
import { ObjcHook } from "./objcHook";

/**
 * IMPORTANT: This is just a place holder file!
 * At the moment, only native hooks can be used on iOS
 */
export class IosHookManager extends HookManager<InputObjcHookNormalized, ObjcHook, NativePointer> {
  constructor(platformStackTrace: PlatformStackTrace) {
    super(ObjcDecoderResolver, platformStackTrace);
  }
  async resolveHooks(inputHooks: InputObjcHookNormalized[], timeout: number): Promise<Promise<ObjcHook[] | null>[]> {
    return [];
  }

  registerHooks(hooks: ObjcHook[]): number {
    return 0;
  }
}
