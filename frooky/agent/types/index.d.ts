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


export type DecodeAt = 'entry' | 'exit' | 'both'

export type ParameterOptions = {
  decoder?: string
  decodeAt?: DecodeAt
  decoderArgs?: string[]
}

export type Parameter =
  | string
  | [string, string]
  | [string, string, ParameterOptions]

// ============================================================================
// Java / Android
// ============================================================================
export interface JavaOverload {
  params: Parameter[]
}

export type JavaMethod =
  | string
  | {
      name: string
      overloads?: JavaOverload[]
  }

export interface JavaHook {
  javaClass: string
  methods: JavaMethod[]
  stackTraceLimit?: number
  stackTraceFilter?: string[]
  debug?: boolean
}

// ============================================================================
// Objective-C / iOS
// ============================================================================

export type ObjectiveCMethod =
  | string
  | {
      name: string
      returnType?: string
      params?: Parameter[]
  }

export interface ObjectiveCHook {
  objcClass: string
  methods: ObjectiveCMethod[]
  stackTraceLimit?: number
  stackTraceFilter?: string[]
  debug?: boolean
}

// ============================================================================
// Native
// ============================================================================
export interface NativeFunction {
  symbol: string
  returnType?: string
  params?: Parameter[]
}

export interface NativeHook {
  module: string
  functions: NativeFunction[]
  stackTraceLimit?: number
  stackTraceFilter?: string[]
  debug?: boolean
}

// ============================================================================
// Union
// ============================================================================
export type Hook = JavaHook | ObjectiveCHook | NativeHook

/**
 * Root frooky configuration.
 */
export interface FrookyConfig {
  /** Optional metadata about the hook collection */
  metadata?: HookMetadata;
  /** Collection of hook configurations */
  hooks: Hook[];
}
