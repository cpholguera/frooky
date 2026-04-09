import type { ObjcHook, ObjcMethodDefinition } from '../../hook/objcHook';
import type { MethodName } from '../../../shared/hook/hook';

/**
 * Objc method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type ObjcMethod = MethodName | ObjcMethodDefinition;


/** 
 * Native hook configuration.
 *
 * Extended type for YAML input parsing.
 * 
 * @public
 * @discriminator {type}
 */

export interface ObjcHookInput extends Omit<ObjcHook, 'methods'> {
  methods: ObjcMethod[];
}