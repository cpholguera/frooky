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
export type direction = 'in' | 'out';


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
   /** Name of the Java type such as "[B", "java.lang.string", "org.owasp.mastestapp.returnValue"*/
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
  retDecoder?: JavaDecoder
}

/**
 * Native function argument descriptor.
 * Defines how arguments should be captured.
 */
export interface NativeArgumentDescriptor {
  name: string;
  type: NativeArgType;
  /** Fixed buffer length */
  length?: number;
  /** Index of argument containing buffer length */
  lengthInArg?: number;
  /** Argument direction: 'in' (default) or 'out' for output parameters */
  direction?: direction;
  /** Set to true to capture the function's return value */
  returnValue?: boolean;
}

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
  /** Enable verbose logging for troubleshooting */
  debug?: boolean;
}

/**
 * Android Java/Kotlin class hooking configuration.
 */
export interface JavaHook extends BaseHook {
  /** Fully qualified class name */
  javaClass: string;
  methods: JavaMethod[];
  /** Methods to call before hooking (e.g., class initialization) */
  prerequisites?: JavaMethod[];
}

/**
 * Native C/C++ function hooking configuration.
 * Native hooks intercept C/C++ functions.
 */
export interface NativeHook extends BaseHook {
  /** Function symbol name or address */
  symbol: string;
  /** Argument descriptors defining how to capture function parameters */
  args?: NativeArgumentDescriptor[];
}

/**
 * iOS Objective-C method hooking configuration.
 * Hook Objective-C methods using objClass and symbol.
 */
export interface ObjectiveCHook extends Omit<BaseHook, 'module'> {
  /** Objective-C class name */
  objClass: string;
  /** Method selector */
  symbol: string;
  module?: string;
  args?: NativeArgumentDescriptor[];
}

/**
 * iOS Swift method hooking configuration.
 */
export interface SwiftHook extends Omit<BaseHook, 'module'> {
  /** Swift class name */
  swiftClass: string;
  /** Mangled Swift symbol */
  symbol: string;
  module?: string;
  args?: NativeArgumentDescriptor[];
}

/**
 * Union type for all supported hook configurations.
 */
export type Hook = JavaHook | NativeHook | ObjectiveCHook | SwiftHook;

/**
 * Category-based hook configuration for MASTG test cases.
 */
export interface CategoryConfig {
  /** Category specified in the hook file */
  category: MasCategory;
  /** Array of hooks to apply for this category */
  hooks: Hook[];
}

/**
 * Root configuration: array of categorized hooks for security testing.
 * When multiple hook files are provided, their hooks arrays are merged.
 */
export type Config = CategoryConfig[];
