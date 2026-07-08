/**
 * Metadata that describes a hook collection.
 *
 * @public
 */
export interface HookSettings {
  /**
   * Sets stackTraceLimit to the given value for all hooks.
   */
  stackTraceLimit: number;

  /**
   * Stack trace filters to apply.
   */
  stackTraceFilter: string[];
}

/**
 * Decoder settings any kind of parameter or return type decoder
 *
 * @public
 */
export interface DecoderSettings {
  /**
   * Maximum recursion depth for nested structure decoding.
   *
   * @example 10
   */
  maxRecursion: number;

  /**
   * Maximum number of elements to decode in lists, arrays, collections, maps etc.. May be increased when decoding 'char *' or 'void *' data types in native code.
   *
   * @example 1000
   */
  decodeLimit: number;

  /**
   * When enabled, frooky tries to guess the type of a value in case it is not declared in the hook, or it is not possible to deduct it at runtime.
   *
   * @defaultValue false
   */
  magicDecode: boolean;

  /**
   * When enabled, the decoders are instructed to prioritize speed over details. Mostly, this mean avoiding expensive Frida <-> native roundtrip.
   *
   * @defaultValue false
   */
  fastDecode: boolean;

  /**
   * Overrides the type decoder.
   *
   * @defaultValue undefined
   */
  customDecoder?: string;

  /**
   * Arguments form the arguments list passed to the decoder.
   *
   * @defaultValue undefined
   */
  decoderArg?: string;

  /**
   * Regular expressions for how an argument is filtered
   *
   * @defaultValue undefined
   */
  paramFilter?: string[];
}

export interface FrookySettings {
  hookSettings: HookSettings;
  decoderSettings: DecoderSettings;
}
