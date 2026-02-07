// types/index.d.ts

/**
 * OWASP MAS (Mobile Application Security) risk categories.
 * Used to classify security hooks by their testing domain.
 */
export type MasCategory =
  | 'STORAGE'
  | 'CRYPTO'
  | 'AUTH'
  | 'NETWORK'
  | 'PLATFORM'
  | 'CODE'
  | 'RESILIENCE'
  | 'PRIVACY';

/**
 * Frida native type mappings for function arguments.
 */
export type NativeArgType =
  | 'string'       // Null-terminated C string
  | 'int32'        // 32-bit signed integer
  | 'uint32'       // 32-bit unsigned integer
  | 'int64'        // 64-bit signed integer
  | 'pointer'      // Memory address
  | 'bytes'        // Raw bytes (requires length or lengthInArg)
  | 'bool'         // Boolean value
  | 'double'       // 64-bit floating point
  | 'CFData'       // iOS CFData object
  | 'CFDictionary'; // iOS CFDictionary object

/**
 * Argument direction for pointer/buffer types.
 */
export type Direction = 'in' | 'out';

/**
 * Base configuration for all hook types.
 */
export interface BaseHook {
  /** Library/framework name */
  module?: string;
  /** Maximum number of stack frames to capture */
  stackTraceLimit?: number;
  /** Regex patterns to filter stack traces */
  stackTraceFilter?: string[];
  /** Enable verbose logging for troubleshooting. */
  debug?: boolean;
}


/**
 * Decoder for a JavaType
 * 
 * By default, frooky will choose the appropriate decoder, but sometimes it is necessary
 * to manually set them
 * 
 * An example is `android.content.Intent.setFlags(int flags)`. If you want to decode the 
 * argument `int flags` with a custom decoder, you must set the name of the decoder here.
 * 
 * The decoders available can be found in `./android/decoders`. 
 */
export type JavaDecoder = string

/**
 * Java type
 * Specify exact method signatures using overloads.
 */
export interface JavaType {
  /** Java type descriptor such as "[B", "java.lang.string", "org.owasp.mastestapp.returnValue"*/
  name: string;
  /** 
   * Optional type decoder. By default, frooky will choose a default decoder. 
   * This can be overruled for example if an integer should be decoded as a FLAG. 
   */
  decoder?: JavaDecoder
}


/**
 * Java method overload signature.
 * Specify exact method signatures using overloads.
 */
export interface JavaOverload {
  args: JavaType[];
}

/**
 * Java method to hook.
 */
export interface JavaMethod {
  name: string;
  /** Optional overloads. If not set, the method without arguments is defined.*/
  overloads?: JavaOverload[];
  /** Optional custom decoder for the return value.*/
  decoder?: JavaDecoder
  // /** 
  //  * Method which will trigger the hooking of the methods. --> TODO: Address recursion issue
  // */
  // prerequisites?: JavaMethod[];
}


/**
 * Android Java/Kotlin class hooking configuration.
 */
export interface JavaHook extends BaseHook {
  /** 
   * Fully qualified class name. 
   * Nested classes are identified with $, wildcards are supported per package level. 
   * Example: `org.owasp.*.Http$Client`: `$Client` is an nested class within `$Http` 
   * and `org.owasp.e.Http$Client` would be a valid match, 
   * but `org.owasp.a.b.c.Http$Client` not.
   * */
  javaClass: string;
  methods: JavaMethod[];
}


/**
 * Native function argument descriptor.
 * Defines how arguments should be captured.
 */
export interface NativeArgDescriptor {
  name: string;
  type: NativeArgType;
  /** Fixed buffer length */
  length?: number;
  /** Index of argument containing buffer length */
  lengthInArg?: number;
  /** Argument direction: 'in' (default) or 'out' for output parameters */
  direction?: Direction;
  /** Set to true to capture the function's return value */
  retValue?: boolean;
}


/**
 * Native C/C++ function hooking configuration.
 * Native hooks intercept C/C++ functions.
 */
export interface NativeHook extends BaseHook {
  /** Function symbol name or address */
  symbol: string;
  /** Argument descriptors defining how to capture function parameters */
  args?: NativeArgDescriptor[];
}

/**
 * iOS Objective-C method hooking configuration.
 * Hook Objective-C methods using objClass and symbol.
 */
export interface ObjectiveCHook extends BaseHook {
  /** Objective-C class name */
  objClass: string;
  /** Method selector */
  symbol: string;
  args?: NativeArgDescriptor[];
}

/**
 * iOS Swift method hooking configuration.
 */
export interface SwiftHook extends BaseHook {
  /** Swift class name */
  swiftClass: string;
  /** Mangled Swift symbol */
  symbol: string;
  args?: NativeArgDescriptor[];
}

/**
 * Union type for all supported hook configurations.
 */
export type Hook = JavaHook | NativeHook | ObjectiveCHook | SwiftHook;

/**
 * Root hooks: array of categorized hooks for testing.
 * When multiple hook files are provided, their hooks arrays are merged.
 */
export interface Hooks {
  /** 
   * OWASP Category specified in the hook file.
   * 
   * TODO: DISCUSSION: I think this should be optional, as otherwise it may look like that frooky
   * is only for security testing. But we should not limit the usage by enforcing a MAS category.
   * 
   */
  category?: MasCategory;
  /** Array of hooks to apply for this category */
  hooks: Hook[];
}
