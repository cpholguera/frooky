import type { ObjcHook, ObjcMethodDefinition } from '../../ios/hook/objcHook';
import type { Hook, MethodName } from '../hook/hook';

/**
 * Objc method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type ObjcMethodInput = MethodName | ObjcMethodDefinition;


/** 
 * Native hook configuration.
 *
 * Extended type for YAML input parsing.
 * 
 * @public
 * @discriminator {type}
 */

export interface ObjcHookInput extends Omit<ObjcHook, 'methods'> {
  methods: ObjcMethodInput[];
}

// Type guard functions
function isObjcHook(h: Hook): h is ObjcHook {
  return h.type === 'objc';
}
