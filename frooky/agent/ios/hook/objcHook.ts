import type { FrookyReturnType, Hook, MethodName } from "../../shared/hook/hook";
import type { Param } from "../../shared/hook/param";

/**
 * Expanded Objective-C method definition with name and optional overloads.
 *
 * @public
 */
export interface ObjcMethodDefinition {
  name: MethodName;
  returnType?: FrookyReturnType;
  params?: Param[];
}

/**
 * Objective-C method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type ObjcMethod = ObjcMethodDefinition;

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
