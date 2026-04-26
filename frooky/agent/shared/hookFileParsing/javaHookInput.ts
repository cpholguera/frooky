import type { JavaHook, JavaMethodDefinition, JavaOverload } from "../../android/hook/javaHook";
import type { Hook, MethodName } from "../hook/hook";
import { normalizeParam, type ParamInput } from "./paramInput";

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
  type: "java";
  methods: JavaMethod[];
}

// Type guard function
export function isJavaHook(h: Hook): h is JavaHook {
  return "javaClass" in h;
}

// will return a JavaOverload for any form of JavaOverloadInput
function normalizeOverload(input: JavaOverloadInput): JavaOverload {
  return {
    ...input,
    params: input.params.map(normalizeParam),
  };
}

// will return a JavaMethodDefinition for any form of JavaMethodDefinitionInput or a simple method string
function normalizeMethod(input: JavaMethodDefinitionInput | string): JavaMethodDefinition {
  if (typeof input === "string") {
    return { name: input };
  }

  return {
    ...input,
    overloads: input.overloads?.map(normalizeOverload),
  };
}

// will return a JavaHook for any form of JavaHookInput
export function normalizeJavaHook(input: JavaHookInput): JavaHook {
  return {
    ...input,
    methods: input.methods.map(normalizeMethod),
  };
}
