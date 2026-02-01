// tests/android/test-runner.ts
import { runTests } from '../test-framework';
import Java from "frida-java-bridge";

// Import all test files
import './test-util';
import './test-decoder';

Java.perform(() => {
    setTimeout(() => {
        runTests(send);
    }, 1000);
});

