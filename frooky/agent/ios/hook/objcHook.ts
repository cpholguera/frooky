import type { Param, RetType } from "../../shared/decoders/decodableTypes";
import type { Hook } from "../../shared/hook/hook";

/**
 * Expanded Objective-C method definition with name and optional overloads.
 *
 * @public
 */
export interface ObjcMethod {
  name: string;
  returnType?: RetType;
  params?: Param[];
}

/**
/**
 * Objective-C hook configuration.
 * @public
 */
export interface ObjcHook extends Hook {
  /**
   * Fully qualified Objective-C class name.
   */
  objcClass: string;

  /**
   * Methods to hook on the target class.
   */
  methods: ObjcMethod[];
}
