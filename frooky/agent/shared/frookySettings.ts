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
  eventFilter: string[];
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
   * Maximum number of elements to decode in a collection or buffer.
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
   * @defaultValue null
   */
  customDecoder: string;

  /**
   * Arguments form the arguments list passed to the decoder.
   *
   * @defaultValue null
   */
  decoderArgs: string[];
}

export interface FrookySettings {
  hookSettings: HookSettings;
  decoderSettings: DecoderSettings;
}
