import type { MethodName, Param } from '../parameter';
import type { ReturnType } from '../returnType';
import type { BaseHook } from './baseHook';

/**
 * Expanded Objective-C method definition with name and optional overloads.
 *
 * @public
 */
export interface ObjCMethodDefinition {
  name: MethodName;
  returnType?: ReturnType;
  params?: Param[];
}

/**
 * Objective-C method selector — either a simple method name or a detailed definition.
 * 
 * @public
 */
export type ObjCMethod = MethodName | ObjCMethodDefinition;


/**
 * Objective-C hook configuration.
 *
 * @public
 */
export interface ObjCHook extends BaseHook {
  /**
   * Fully qualified Objective-C class name.
   */
  objcClass: string;

  /**
   * Methods to hook on the target class.
   */
  methods: ObjCMethod[];

}


