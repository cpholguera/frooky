// very simple testing framework runnable in a frida environment

interface Matcher<T> {
  toBe(expected: T): void;
  toEqual(expected: T): void;
  toBeTruthy(): void;
  toBeFalsy(): void;
  toThrow(errorMatch?: string | Error): void;
  notToThrow(): void;
}

declare global {
  function describe(name: string, fn: () => void | Promise<void>): void;
  function it(name: string, fn: () => void | Promise<void>): void;
  function expect<T>(actual: T): Matcher<T>;
}

export {};

interface TestResult {
  name: string;
  passed: boolean;
  depth: number;
  error?: string;
  children?: TestResult[];
}

type TestMessage = { type: "test-result"; result: TestResult } | { type: "test-complete"; success: boolean; results: TestResult[] };

const topLevelTests: Array<{ name: string; fn: () => void | Promise<void> }> = [];
const suiteStack: Array<Array<{ name: string; fn: () => void | Promise<void> }>> = [];

const registerTest = (name: string, fn: () => void | Promise<void>) => {
  const current = suiteStack[suiteStack.length - 1];
  (current ?? topLevelTests).push({ name, fn });
};

globalThis.describe = registerTest;
globalThis.it = registerTest;

const assert = (condition: boolean, message: string) => {
  if (!condition) throw new Error(message);
};

const deepEqual = <T>(a: T, b: T): boolean => {
  if (a === b) return true;
  if (a == null || b == null || typeof a !== "object" || typeof b !== "object") return false;
  const keysA = Object.keys(a);
  if (keysA.length !== Object.keys(b).length) return false;
  return keysA.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
};

globalThis.expect = <T>(actual: T): Matcher<T> => ({
  toBe: (expected) => assert(actual === expected, `Expected ${actual} to be ${expected}`),

  toEqual: (expected) => assert(deepEqual(actual, expected), `Expected ${JSON.stringify(actual)} to equal ${JSON.stringify(expected)}`),

  toBeTruthy: () => assert(!!actual, `Expected ${actual} to be truthy`),

  toBeFalsy: () => assert(!actual, `Expected ${actual} to be falsy`),

  toThrow: (errorMatch) => {
    assert(typeof actual === "function", "Expected a function");
    let caughtError: unknown;
    try {
      (actual as () => void)();
    } catch (e) {
      caughtError = e;
    }
    assert(caughtError !== undefined, "Expected function to throw");
    if (!errorMatch || !(caughtError instanceof Error)) return;
    if (typeof errorMatch === "string") {
      assert(caughtError.message.includes(errorMatch), `Expected error message to include "${errorMatch}" but got "${caughtError.message}"`);
    } else {
      assert(
        caughtError instanceof errorMatch.constructor && caughtError.message === errorMatch.message,
        `Expected ${errorMatch.constructor.name}: "${errorMatch.message}" but got ${(caughtError as Error).constructor.name}: "${caughtError.message}"`,
      );
    }
  },

  notToThrow: () => {
    assert(typeof actual === "function", "Expected a function");
    let caughtError: unknown;
    try {
      (actual as () => void)();
    } catch (e) {
      caughtError = e;
    }
    assert(
      caughtError === undefined,
      `Expected function not to throw but got ${caughtError instanceof Error ? `${caughtError.constructor.name}: "${caughtError.message}"` : String(caughtError)}`,
    );
  },
});

async function runSuite(name: string, fn: () => void | Promise<void>, depth: number): Promise<TestResult> {
  const children: Array<{ name: string; fn: () => void | Promise<void> }> = [];
  suiteStack.push(children);

  let passed = true;
  let error: string | undefined;
  try {
    await fn();
  } catch (e) {
    passed = false;
    error = e instanceof Error ? e.message : String(e);
  } finally {
    suiteStack.pop();
  }

  const childResults = await Promise.all(children.map((c) => runSuite(c.name, c.fn, depth + 1)));
  if (childResults.some((c) => !c.passed)) passed = false;

  return {
    name,
    passed,
    depth,
    error,
    children: childResults.length > 0 ? childResults : undefined,
  };
}

export async function runTests(sendCallback: (message: TestMessage) => void): Promise<void> {
  const suitesToRun = [...topLevelTests];
  topLevelTests.length = 0;

  if (suitesToRun.length === 0) {
    sendCallback({ type: "test-complete", success: true, results: [] });
    return;
  }

  const allResults: TestResult[] = [];
  for (const suite of suitesToRun) {
    const result = await runSuite(suite.name, suite.fn, 0);
    allResults.push(result);
    sendCallback({ type: "test-result", result });
  }

  sendCallback({
    type: "test-complete",
    success: allResults.every((r) => r.passed),
    results: allResults,
  });
}
