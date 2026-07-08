import ObjC from "frida-objc-bridge";
import { Param } from "../../shared/decoders/decodable";
import { Hook } from "../../shared/hook/hook";

/**
 * IMPORTANT: This is just a place holder file!
 * At the moment, only native hooks can be used on iOS
 */
export interface ObjcHook extends Hook {
  method: ObjC.ObjectMethod;
  methodName: string;
  params?: Param[];
}
