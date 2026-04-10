import type { Hook, MethodName, ReturnType } from "../../shared/hook/hook";
import type { Param } from "../../shared/hook/parameter";

/**
 * Expanded Objective-C method definition with name and optional overloads.
 *
 * @public
 */
export interface ObjcMethodDefinition {
  name: MethodName;
  returnType?: ReturnType;
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
 * @discriminator {type}
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

// Type guard function
export function isObjcHook(h: Hook): h is ObjcHook {
  return "objcClass" in h;
}
