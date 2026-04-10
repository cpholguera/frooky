import Java from 'frida-java-bridge';
import type { Hook, MethodName } from '../../shared/hook/hook';
import type { Param } from '../../shared/hook/parameter';

/**
 * Describes a specific Java method overload.
 *
 * @public
 */
export interface JavaOverload {
    /**
     * Parameter definitions for this overload.
     */
    params: Param[];
}

/**
 * Expanded Java method definition with name and optional overloads.
 *
 * @public
 */
export interface JavaMethodDefinition {
    /**
     * Method name.
     */
    name: MethodName;

    /**
     * Explicit overload definitions.
     */
    overloads?: JavaOverload[];
}

/**
 * Java method selector
 *
 * @public
 */
export type JavaMethod = JavaMethodDefinition;

/**
 * Native hook configuration.
 *
 * @public
 * @discriminator {type}
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

// Type guard function
export function isJavaHook(h: Hook): h is JavaHook {
  return 'javaClass' in h;
}

