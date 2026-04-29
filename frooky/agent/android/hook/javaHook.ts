import { Param, RetType } from "../../shared/decoders/decodableTypes";
import type { Hook, MethodName } from "../../shared/hook/hook";


/**
 * Describes a specific Java method overload.
 *
 * @public
 */
export interface JavaOverload {
  /**
   * Parameter definitions for this overload.
   */
  params: Param[];
}

/**
 * Expanded Java method definition with name and optional overloads.
 *
 * @public
 */
export interface JavaMethodDefinition {
  name: MethodName;
  returnType?: RetType;
  overloads?: JavaOverload[];
}

/**
 * Java method selector
 *
 * @public
 */
export type JavaMethod = JavaMethodDefinition;

/**
 * Native hook configuration.
 *
 * @public
 */
export interface JavaHook extends Hook {
  /**
   * Fully qualified Java class name.
   */
  javaClass: string;

  /**
   * Methods to hook on the target class.
   */
  methods: JavaMethod[];
}
