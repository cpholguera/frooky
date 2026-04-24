import type { ObjcHook, ObjcMethodDefinition } from "../../ios/hook/objcHook";
import type { MethodName, ReturnType } from "../hook/hook";
import { normalizeParam, type ParamInput } from "./parameterInput";

/**
 * Expanded Objective-C method definition with name and optional overloads.
 *
 * @public
 */
export interface ObjcMethodDefinitionInput {
  name: MethodName;
  returnType?: ReturnType;
  params?: ParamInput[];
}

/**
 * Objc method selector — either a simple method name or a detailed definition.
 *
 * @public
 */
export type ObjcMethodInput = MethodName | ObjcMethodDefinitionInput;

/**
 * Native hook configuration.
 *
 * Extended type for YAML input parsing.
 *
 * @public
 * @discriminator {type}
 */

export interface ObjcHookInput extends Omit<ObjcHook, "methods"> {
  type: "objc";
  methods: ObjcMethodInput[];
}

// returns a normalized ObjcMethodDefinition from any type of ObjcMethodInput
function normalizeObjcMethod(input: ObjcMethodInput): ObjcMethodDefinition {
  if (typeof input === "string") {
    return { name: input };
  }

  return {
    ...input,
    params: input.params?.map(normalizeParam),
  };
}

export function normalizeObjcHook(input: ObjcHookInput): ObjcHook {
  return {
    ...input,
    methods: input.methods.map(normalizeObjcMethod),
  };
}
