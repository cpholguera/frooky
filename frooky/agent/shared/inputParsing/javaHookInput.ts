import type { JavaHook, JavaMethodDefinition, JavaOverload } from '../../android/hook/javaHook';
import type { MethodName } from '../hook/hook';
import type { ParamYamlInput } from './parameterInput';


/**
 * Describes a specific Java method overload.
 * Extended type for YAML input parsing.
 * @public
 */
export interface JavaOverloadYamlParsing extends Omit<JavaOverload, 'params'> {
  /**
   * Parameter definitions for this overload.
   */
  params: ParamYamlInput[];
}


/**
 * Extended type for YAML input parsing.
 *
 * @public
 */
export interface JavaMethodDefinitionInput extends Omit<JavaMethodDefinition, 'overloads'> {
  /**
   * Explicit overload definitions.
   */
  overloads?: JavaOverloadYamlParsing[];
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
 * Extended type for YAML input parsing.
 * 
 * @public
 * @discriminator {type}
 */

export interface JavaHookInput extends Omit<JavaHook, 'methods'> {
  methods: JavaMethod[];
}
