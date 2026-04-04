import { runTests } from '../agent-test-framework';
import Java from "frida-java-bridge";

// Import all test files
import './test-util';
import './test-decoder';
import './test-runtime';

Java.perform(() => {
    setTimeout(() => {
        runTests(send);
    }, 1000);
});