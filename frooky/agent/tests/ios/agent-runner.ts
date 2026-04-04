// tests/ios/agent-runner.ts
import { runTests } from '../agent-test-framework';


// Import all ios test files
import './test-method-resolver';
import './test-runtime';

setTimeout(() => {
    runTests(send);
}, 1000);
