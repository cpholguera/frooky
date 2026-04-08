import type { Param } from '../parameter';
import type { BaseHook, MethodName } from './baseHook';

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
  /**
   * Method name.
   */
  name: MethodName;

  /**
   * Explicit overload definitions.
   */
  overloads?: JavaOverload[];
}

/**
 * Java method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type JavaMethod = MethodName | JavaMethodDefinition;

/**
 * Native hook configuration.
 *
 * @public
 * @discriminator {type}
 */
export interface JavaHook extends BaseHook {
  /**
  * Internally used type guard.
  */
  type: "java"

  /**
   * Fully qualified Java class name.
   */
  javaClass: string;

  /**
   * Methods to hook on the target class.
   */
  methods: JavaMethod[];

}

