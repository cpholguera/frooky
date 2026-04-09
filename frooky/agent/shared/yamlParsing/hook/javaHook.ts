import type { JavaHook, JavaMethodDefinition } from '../../hook/javaHook';
import type { MethodName } from '../../../shared/hook/baseHook';

/**
 * Java method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type JavaMethod = MethodName | JavaMethodDefinition;


/**
 * Native hook configuration.
 * 
 * Extended type for YAML input parsing.
 * 
 * @public
 * @discriminator {type}
 */

export interface JavaHookInput extends Omit<JavaHook, 'methods'> {
  methods: JavaMethod[];
}