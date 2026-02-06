/**
 * Generates a v4 UUID
 * @returns {string} v4 UUID (e.g. "6b5354ed-8c3e-476d-8999-96b2251d8a3c")
 */
export function uuidv4(): string {
    return "10000000-1000-4000-8000-100000000000".replace(
        /[018]/g,
        (c: string): string =>
            ((+c ^ Math.random() * 16 >> +c / 4) & 15).toString(16)
    );
}

/**
 * Makes a hex dump of a byte array. The dump is limited by the length parameter.
 * @param bytes - Bytes to be decoded to hexadecimal.
 * @param length - Number of bytes which will be decoded. If not provided, all bytes are decoded.
 * @returns The hexadecimal decoded bytes (e.g., "0x22aa3482ef...")
 */
export function toHexString(bytes: Uint8Array, length: number = Infinity): string {
    if (length < 0) {
        throw new RangeError("Length cannot be negative");
    }
    const lengthToDecode = Math.min(bytes.length, length);
    const appendix = bytes.length > length ? "..." : "";
    
    const hexString = Array.from(bytes.subarray(0, lengthToDecode))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");

    return "0x" + hexString + appendix;
}
