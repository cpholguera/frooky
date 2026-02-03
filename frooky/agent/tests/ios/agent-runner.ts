// tests/ios/test-runner.ts
import { runTests } from '../agent-test-framework';


// Import all ios test files
import './test-method-resolver';

setTimeout(() => {
    runTests(send);
}, 1000);
