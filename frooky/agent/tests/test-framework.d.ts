// tests/test-framework.d.ts

// very simple testing framework runnable in a frida environment

declare global {
    function test(name: string, fn: () => void | Promise<void>): void;

    function expect(actual: any): {
        toBe(expected: any): void;
        toEqual(expected: any): void;
        toBeTruthy(): void;
        toBeFalsy(): void;
        toThrow(): void;
    };
}

export {};
