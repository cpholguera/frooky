import { Param, RetType } from "../../shared/decoders/decodableTypes";
import { DecoderSettings } from "../../shared/decoders/decoderSettings";
import type { Hook, MethodName } from "../../shared/hook/hook";
import { JavaParam } from "./javaParam";


/**
 * Describes a specific Java method overload.
 *
 * @public
 */
export interface JavaOverload {
  /**
   * Parameter definitions for this overload.
   */
  params: JavaParam[];
}

/**
 * Expanded Java method definition with name and optional overloads.
 *
 * @public
 */
export interface JavaMethod {
  name: string;
  retType?: RetType;
  overloads?: JavaOverload[];
  decoderSettings: DecoderSettings
}

/**
 * Native hook configuration.
 *
 * @public
 */
export interface JavaHook extends Hook {
  /**
   * Fully qualified Java class name.
   */
  javaClass: string;

  /**
   * Methods to hook on the target class.
   */
  methods: JavaMethod[];
}
