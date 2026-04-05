// very simple testing framework runnable in a frida environment

interface Matcher<T = unknown> {
    toBe(expected: T): void;
    toEqual(expected: T): void;
    toBeTruthy(): void;
    toBeFalsy(): void;
    toThrow(errorMatch?: string | Error): void;
}

declare global {
    function test(name: string, fn: () => void | Promise<void>): void;
    function expect<T>(actual: T): Matcher<T>;
}

export {};