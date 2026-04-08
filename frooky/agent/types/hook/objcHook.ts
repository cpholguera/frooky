import type { Param } from '../parameter';
import type { ReturnType } from '../returnType';
import type { BaseHook, MethodName } from './baseHook';

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
 * @public
 * @discriminator {type}
 */
export interface ObjCHook extends BaseHook {
  /**
  * Internally used type guard.
  */
  type: "objc"

  /**
   * Fully qualified Objective-C class name.
   */
  objcClass: string;

  /**
   * Methods to hook on the target class.
   */
  methods: ObjCMethod[];

}


