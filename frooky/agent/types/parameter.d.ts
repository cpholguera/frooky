
/**
 * Specifies when a decoder should be applied during function execution.
 *
 * @example "enter" - Decode when the function/method is entered (before execution)
 * @example "exit" - Decode when the function/method returns (after execution)
 * @example "both" - Decode at both times
 *
 * @public
 */
export type DecodeAt = 'enter' | 'exit' | 'both';



/**
 * Frida-compatible type of the parameter.
 *
 * @example "java.lang.String"
 * @example "[Ljava.lang.Object;"
 * @example "[Z"
 * @example "int"
 * 
 * @public
 */
export type ParamType = string

/**
 * Parameter name.
 *
 * @example "username"
 * @example "buffer"
 * @example "url"
 * 
 * @public
 */
export type ParamName = string


/**
 * Decoder options for a parameter.
 *
 * @public
 */
export interface ParamOptions {
  /**
   * When the decoder should be applied.
   *
   * @defaultValue "enter"
   * @example [ "exit" ]
   * @example [ "both" ]
   */
  decodeAt?: DecodeAt;


  /**
   * Extra arguments passed to the decoder. They must be a valid parameter name. 
   * 
   * @example [ "username" ]
   * @example [ "ctxPointer" ]
   * @example [ "inBuffer", "bufferLength" ]
   */
  decoderArgs?: string[];
}


/**
 * Parameter definition can be provided in multiple forms.
 * 
 * The following examples all describe the same parameter:
 *
 * 1. As a simple type name.
 * 2. As a tuple of [type, options].
 * 3. As a tuple of [type, name, options].
 * 4. As a structured object with type, name, and options.
 *
 * @example "java.lang.String"
 * @example ["java.lang.String", { decodeAt: "exit" }]
 * @example ["java.lang.String", "value", { decodeAt: "exit" }]
 * @example { type: "java.lang.String", name: "value", options: { decodeAt: "exit" } }
 *
 * @public
 */
export type Param =
  | ParamType
  | [ParamType, ParamOptions]
  | [ParamType, ParamName, ParamOptions]
  | {
      type: ParamType;
      name?: ParamName;
      options?: ParamOptions;
    };

/**
 * Name of a Java or Objective-C method.
 *
 * @public
 */
export type MethodName = string;
