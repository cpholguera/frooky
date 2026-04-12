import type { JavaHook, JavaMethodDefinition, JavaOverload } from "../../android/hook/javaHook";
import type { MethodName } from "../hook/hook";
import { normalizeParam, type ParamInput } from "./parameterInput";

/**
 * Describes a specific Java method overload.
 * Extended type for YAML input parsing.
 * @public
 */
export interface JavaOverloadInput extends Omit<JavaOverload, "params"> {
  /**
   * Parameter definitions for this overload.
   */
  params: ParamInput[];
}

/**
 * Extended type for YAML input parsing.
 *
 * @public
 */
export interface JavaMethodDefinitionInput extends Omit<JavaMethodDefinition, "overloads"> {
  /**
   * Explicit overload definitions.
   */
  overloads?: JavaOverloadInput[];
}

/**
 * Java method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type JavaMethod = MethodName | JavaMethodDefinitionInput;

/**
 * Native hook configuration.
 *
 * Extended type for YAML input parsing.
 *
 * @public
 * @discriminator {type}
 */

export interface JavaHookInput extends Omit<JavaHook, "methods"> {
  methods: JavaMethod[];
}

function normalizeOverload(input: JavaOverloadInput): JavaOverload {
  return {
    ...input,
    params: input.params.map(normalizeParam),
  };
}

function normalizeMethod(input: JavaMethodDefinitionInput | string): JavaMethodDefinition {
  if (typeof input === "string") {
    return { name: input };
  }

  return {
    ...input,
    overloads: input.overloads?.map(normalizeOverload),
  };
}

export function normalizeJavaHook(input: JavaHookInput): JavaHook {
  return {
    ...input,
    methods: input.methods.map(normalizeMethod),
  };
}
