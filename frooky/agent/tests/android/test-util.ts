import { generateUUID } from "../../android/android-agent"

test('Test UUID generator', () => {
    const uuid = generateUUID();

    // UUID v4 regex pattern
    const uuidV4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    expect(uuidV4Regex.test(uuid)).toBeTruthy();
});
