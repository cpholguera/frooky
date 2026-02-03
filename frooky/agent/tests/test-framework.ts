// tests/test-framework.ts

// very simple testing framework runnable in a frida environment

interface TestResult {
    name: string;
    passed: boolean;
    error?: string;
}

interface TestCompleteMessage {
    type: 'test-complete';
    success: boolean;
    results: TestResult[];
    error?: string;
}

const tests: Array<{ name: string; fn: () => void | Promise<void> }> = [];

// Use globalThis instead of global
(globalThis as any).test = (name: string, fn: () => void | Promise<void>) => {
    tests.push({ name, fn });
};

(globalThis as any).expect = (actual: any) => ({
    toBe: (expected: any) => {
        if (actual !== expected) {
            throw new Error(`Expected ${actual} to be ${expected}`);
        }
    },
    toEqual: (expected: any) => {
        if (JSON.stringify(actual) !== JSON.stringify(expected)) {
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
    toThrow: () => {
        if (typeof actual !== 'function') {
            throw new Error('Expected a function');
        }
        try {
            actual();
            throw new Error('Expected function to throw');
        } catch (e) {
            // Expected to throw
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