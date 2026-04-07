import type { ReturnType } from 'frooky';
import type { MethodName, Param } from '../parameter';
import type { BaseHook } from './baseHook';


/**
 * Expanded Native method definition with name and optional overloads.
 *
 * @public
 */
export interface NativeMethodDefinition {
  symbol: MethodName;
  returnType?: ReturnType;
  params?: Param[];
}

/**
 * Native method selector — either a simple method name or a detailed definition.
 * 
 * @public
 */
export type NativeMethod = MethodName | NativeMethodDefinition;


/**
 * Native hook configuration.
 *
 * @public
 */
export interface NativeHook extends BaseHook {
  /**
   * Fully qualified Native class name.
   */
  objcClass: string;

  /**
   * Methods to hook on the target class.
   */
  methods: NativeMethod[];

}


