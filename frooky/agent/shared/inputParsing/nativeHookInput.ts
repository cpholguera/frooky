import type { NativeHook, SymbolDefinition, SymbolName } from '../hook/nativeHook';
import type { ParamYamlInput } from './parameterInput';

export type { SymbolName };

/**
 * Expanded Native method definition with YAML-parsed parameters.
 *
 * @public
 */
export interface SymbolDefinitionInput extends Omit<SymbolDefinition, 'params'> {
  params?: ParamYamlInput[];
}

/**
 * Native method selector — either a simple method name or a detailed YAML definition.
 *
 * @public
 */
export type NativeSymbol = SymbolName | SymbolDefinitionInput;

/**
 * Native hook configuration for YAML parsing.
 * Extends {@link NativeHook} with a looser `functions` type that accepts
 * both plain symbol names and detailed definitions.
 *
 * @public
 * @discriminator {type}
 */
export interface NativeHookInput extends Omit<NativeHook, 'functions'> {
  functions: NativeSymbol[];
}
