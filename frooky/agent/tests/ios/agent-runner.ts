import { runTests } from '../agent-test-framework';

// Import all ios test files
import '../shared/test-testing';
import './test-method-resolver';
import './test-runtime';

setTimeout(() => {
    runTests(send);
}, 1000);
