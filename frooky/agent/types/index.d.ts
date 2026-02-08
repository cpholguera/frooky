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
 * Target platform for hooks.
 */
export type Platform = 'Android' | 'iOS';

/**
 * When to decode a parameter.
 */
export type DecodeAt = 'enter' | 'exit' | 'both';

/**
 * Base configuration for all hook types.
 */
export interface BaseHook {
  /** Library/framework name. Mandatory for NativeHook. */
  module?: string;
  /** Maximum number of stack frames to capture (default: 10) */
  stackTraceLimit?: number;
  /** Regex patterns to filter stack traces */
  stackTraceFilter?: string[];
  /** Enable verbose logging for troubleshooting */
  debug?: boolean;
}

/**
 * Parameter declaration shared across hook types.
 */
export interface ParameterDeclaration {
  /** Type descriptor according to platform standard */
  type: string;
  /** Optional: Name of the parameter */
  name?: string;
  /** Optional: When to decode the parameter. Default: enter */
  decodeAt?: DecodeAt;
  /** Optional: Custom decoder name. Default: autoSelect */
  decoder?: string;
}

/**
 * Java method overload signature.
 */
export interface JavaOverload {
  /** Parameter list of the overloaded method */
  parameters?: ParameterDeclaration[];
}

/**
 * Java method to hook.
 */
export interface JavaMethod {
  /** Name of the Java method */
  name: string;
  /** Optional: List of explicit method overloads */
  overloads?: JavaOverload[];
}

/**
 * Android Java/Kotlin class hooking configuration.
 */
export interface JavaHook extends BaseHook {
  /** Fully qualified Java class name */
  javaClass: string;
  /** List of Java methods to hook */
  methods: JavaMethod[];
}

/**
 * Objective-C method declaration.
 */
export interface ObjectiveCMethod {
  /** Name of the Objective-C method (include - or + prefix) */
  name: string;
  /** Optional: Return type of the Objective-C method */
  returnType?: string;
  /** Optional: Parameter list of the Objective-C method */
  parameters?: ParameterDeclaration[];
}

/**
 * iOS Objective-C method hooking configuration.
 */
export interface ObjectiveCHook extends BaseHook {
  /** Fully qualified Objective-C class name */
  objClass: string;
  /** List of Objective-C method declarations to be hooked */
  methods: ObjectiveCMethod[];
}

/**
 * Native function declaration.
 */
export interface NativeFunction {
  /** Native symbol as string */
  symbol: string;
  /** Optional: Return type of the function */
  returnType?: string;
  /** Optional: Parameter list of the function */
  parameters?: ParameterDeclaration[];
}

/**
 * Native C/C++ function hooking configuration.
 */
export interface NativeHook extends BaseHook {
  /** Fully qualified module name (mandatory) */
  module: string;
  /** List of native symbol declarations to be hooked */
  functions: NativeFunction[];
}

/**
 * iOS Swift method hooking configuration.
 */
export interface SwiftHook extends BaseHook {
  /** List of mangled Swift symbols */
  methods: string[];
}

/**
 * Union type for all supported hook configurations.
 */
export type Hook = JavaHook | NativeHook | ObjectiveCHook | SwiftHook;

/**
 * Metadata for the hook collection.
 */
export interface HookMetadata {
  /** Optional: Name of the hook collection */
  name?: string;
  /** Optional: Target platform (hooks must be platform-specific) */
  platform?: Platform;
  /** Optional: Description of what the hook collection does */
  description?: string;
  /** Optional: OWASP MAS category */
  masCategory?: MasCategory;
  /** Optional: Your name or organization */
  author?: string;
  /** Optional: Semantic version (e.g., v1) */
  version?: string;
}

/**
 * Root frooky configuration.
 */
export interface FrookyConfig {
  /** Optional metadata about the hook collection */
  metadata?: HookMetadata;
  /** Collection of hook configurations */
  hooks: Hook[];
}
