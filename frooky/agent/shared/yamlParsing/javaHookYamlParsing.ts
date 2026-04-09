import type { JavaHook, JavaMethodDefinition } from '../../android/hook/javaHook';
import type { MethodName } from '../hook/hook';
import type { ParamYamlParsing } from './parameterYamlParsing';


/**
 * Describes a specific Java method overload.
 * Extended type for YAML input parsing.
 * @public
 */
export interface JavaOverloadYamlParsing extends Omit<JavaMethodDefinition, 'params'> {
  /**
   * Parameter definitions for this overload.
   */
  params: ParamYamlParsing[];
}


/**
 * Extended type for YAML input parsing.
 *
 * @public
 */
export interface JavaMethodDefinitionYamlParsing extends Omit<JavaMethodDefinition, 'overloads'> {
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