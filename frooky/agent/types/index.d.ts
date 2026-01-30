// types/index.d.ts

/**
 * OWASP MAS (Mobile Application Security) risk categories
 * Used to classify security hooks by their testing domain
 */
export type MasCategory = 
  | 'STORAGE'     // File system, databases, keychain access
  | 'CRYPTO'      // Cryptographic operations and key management
  | 'AUTH'        // Authentication and session management
  | 'NETWORK'     // Network communications and TLS
  | 'PLATFORM'    // OS-level interactions and permissions
  | 'CODE'        // Code integrity and tampering detection
  | 'RESILIENCE'  // Anti-debugging and runtime protection
  | 'PRIVACY';    // PII handling and data leakage

/**
 * Frida native type mappings for function arguments
 * Maps to Frida's NativeFunction argument types
 */
export type NativeArgType = 
  | 'string' 
  | 'int32' 
  | 'uint32' 
  | 'int64' 
  | 'pointer' 
  | 'bytes' 
  | 'bool' 
  | 'double' 
  | 'CFData'        // iOS Core Foundation data type
  | 'CFDictionary'; // iOS Core Foundation dictionary type

/** Argument direction for pointer/buffer types */
export type direction = 'in' | 'out';

/** Java method overload signature */
export interface JavaOverload {
  args: string[];  // Java type signatures (e.g., 'java.lang.String', 'int')
}

/** Java method to hook */
export interface JavaMethod {
  name: string;
  overloads?: JavaOverload[];  // Required when method has multiple signatures
}

/**
 * Native function argument descriptor
 * Defines how to parse and display function arguments in Frida hooks
 */
export interface NativeArgumentDescriptor {
  name: string;
  type: NativeArgType;
  length?: number;           // Fixed buffer length
  lengthInArg?: number;      // Index of argument containing buffer length
  direction?: direction;     // For pointer types: input or output buffer
  returnValue?: boolean;     // True if this describes the return value
}

/** Base configuration for all hook types */
export interface BaseHook {
  module?: string;              // Library/framework name (e.g., 'libc.so', 'Security')
  stackTraceLimit?: number;     // Max stack frames to capture
  stackTraceFilter?: string[];  // Regex patterns to filter stack traces
  debug?: boolean;              // Enable verbose logging
}

/** Android Java/Kotlin class hooking configuration */
export interface JavaHook extends BaseHook {
  javaClass: string;           // Fully qualified class name
  methods: JavaMethod[];
  prerequisites?: JavaMethod[]; // Methods to call before hooking (e.g., class initialization)
}

/** Native C/C++ function hooking configuration */
export interface NativeHook extends BaseHook {
  symbol: string;              // Function symbol name or address
  args?: NativeArgumentDescriptor[];
}

/** iOS Objective-C method hooking configuration */
export interface ObjectiveCHook extends Omit<BaseHook, 'module'> {
  objClass: string;            // Objective-C class name
  symbol: string;              // Method selector (e.g., '-[Class method:]')
  module?: string;
  args?: NativeArgumentDescriptor[];
}

/** iOS Swift method hooking configuration */
export interface SwiftHook extends Omit<BaseHook, 'module'> {
  swiftClass: string;          // Swift class name
  symbol: string;              // Mangled Swift symbol
  module?: string;
  args?: NativeArgumentDescriptor[];
}

/** Union type for all supported hook configurations */
export type Hook = JavaHook | NativeHook | ObjectiveCHook | SwiftHook;

/** Category-based hook configuration for MASTG test cases */
export interface CategoryConfig {
  category: MasCategory;
  hooks: Hook[];
}

/** Root configuration: array of categorized hooks for testing */
export type Config = CategoryConfig[];
