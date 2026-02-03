// tests/test-framework.ts

// very simple testing framework runnable in a frida environment

interface TestResult {
    name: string;
    passed: boolean;
    error?: string;
}

interface Matcher {
    toBe: (expected: any) => void;
    toEqual: (expected: any) => void;
    toBeTruthy: () => void;
    toBeFalsy: () => void;
    toThrow: (errorMatch?: string | RegExp) => void;
}

const tests: Array<{ name: string; fn: () => void | Promise<void> }> = [];

(globalThis as any).test = (name: string, fn: () => void | Promise<void>) => {
    tests.push({ name, fn });
};

(globalThis as any).expect = (actual: any): Matcher => ({
    toBe: (expected: any) => {
        if (actual !== expected) {
            throw new Error(`Expected ${actual} to be ${expected}`);
        }
    },
    toEqual: (expected: any) => {
        // Deep equality check
        const deepEqual = (a: any, b: any): boolean => {
            if (a === b) return true;
            if (a == null || b == null) return false;
            if (typeof a !== 'object' || typeof b !== 'object') return false;

            const keysA = Object.keys(a);
            const keysB = Object.keys(b);
            if (keysA.length !== keysB.length) return false;

            return keysA.every(key => deepEqual(a[key], b[key]));
        };

        if (!deepEqual(actual, expected)) {
            throw new Error(`Expected ${JSON.stringify(actual)} to equal ${JSON.stringify(expected)}`);
        }
    },
    toBeTruthy: () => {
        if (!actual) {
            throw new Error(`Expected ${actual} to be truthy`);
        }
    },
    toBeFalsy: () => {
        if (actual) {
            throw new Error(`Expected ${actual} to be falsy`);
        }
    },
    toThrow: (errorMatch?: string | RegExp) => {
        if (typeof actual !== 'function') {
            throw new Error('Expected a function');
        }
        try {
            actual();
            throw new Error('Expected function to throw');
        } catch (e) {
            if (errorMatch && e instanceof Error) {
                const message = e.message;
                const matches = typeof errorMatch === 'string' 
                    ? message.includes(errorMatch)
                    : errorMatch.test(message);
                if (!matches) {
                    throw new Error(`Expected error message to match ${errorMatch}`);
                }
            }
        }
    }
});


export function runTests(sendCallback: (message: any) => void): void {
    let completedTests = 0;
    const totalTests = tests.length;
    const results: TestResult[] = [];

    if (totalTests === 0) {
        sendCallback({
            type: 'test-complete',
            success: true,
            results: []
        });
        return;
    }

    tests.forEach(test => {
        Promise.resolve()
            .then(() => test.fn())
            .then(() => {
                const result = {
                    name: test.name,
                    passed: true
                };
                results.push(result);
                sendCallback({
                    type: 'test-result',
                    ...result
                });
            })
            .catch(error => {
                const result = {
                    name: test.name,
                    passed: false,
                    error: error instanceof Error ? error.message : String(error)
                };
                results.push(result);
                sendCallback({
                    type: 'test-result',
                    ...result
                });
            })
            .finally(() => {
                completedTests++;
                if (completedTests === totalTests) {
                    sendCallback({
                        type: 'test-complete',
                        success: results.every(r => r.passed),
                        results: results
                    });
                }
            });
    });
}

export function clearTests(): void {
    tests.length = 0;
}