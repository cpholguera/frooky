import type { ObjcHook, ObjcMethodDefinition } from '../../ios/hook/objcHook';
import type { MethodName } from '../hook/hook';

/**
 * Objc method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type ObjcMethodYamlParsing = MethodName | ObjcMethodDefinition;


/** 
 * Native hook configuration.
 *
 * Extended type for YAML input parsing.
 * 
 * @public
 * @discriminator {type}
 */

export interface ObjcHookYamlParsing extends Omit<ObjcHook, 'methods'> {
  methods: ObjcMethodYamlParsing[];
}