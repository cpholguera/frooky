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

const HEX_TABLE:  readonly string[] = Object.freeze(
    Array.from({ length: 256 }, (_, i) => 
        (i < 16 ? '0' : '') + i.toString(16)
    )
);

/**
 * Determines the actual length to decode and whether ellipsis is needed.
 * @param bytes - Bytes array to check length against.
 * @param length - Maximum number of bytes to decode.
 * @returns A tuple [lengthToDecode, ellipsis] where lengthToDecode is the actual length and ellipsis is "..." or "".
 * @throws {RangeError} If length is negative.
 */
function getDecodeBounds(bytes: Uint8Array, length: number): [number, string] {
    if (length < 0) {
        throw new RangeError("Length cannot be negative");
    }

    if (bytes.length > length) {
        return [length, "..."];
    }
    return [bytes.length, ""];
}

/**
 * Checks if a byte is printable ASCII.
 * @param byte - Byte value to check.
 * @returns True if the byte represents a printable character (32-126) or tab/newline/carriage return.
 */
function isPrintable(byte: number): boolean {
    return (byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13;
}

/**
 * Fast bytes to hexadecimal conversion.
 * @param bytes - Bytes to be decoded as hexadecimal.
 * @param length - Number of bytes which will be decoded. Defaults to Infinity.
 * @returns The hexadecimal decoded bytes (e.g., "0x22aa3482ef...")
 * @throws {RangeError} If length is negative.
 */
export function toHex(bytes: Uint8Array, length: number = Infinity): string {
    const [lengthToDecode, ellipsis] = getDecodeBounds(bytes, length);
    const hexArray = new Array(lengthToDecode);

    for (let i = 0; i < lengthToDecode; i++) {
        const byte = bytes[i];
        hexArray[i] = HEX_TABLE[byte];
    }

    return "0x" + hexArray.join("") + ellipsis;
}

/**
 * Fast bytes to ascii conversion.
 * @param bytes - Bytes to be decoded as ascii.
 * @param length - Number of bytes which will be decoded. Defaults to Infinity.
 * @param placeholder - Placeholder for ascii representation of not-printable bytes. Defaults to "."
 * @returns The decoded bytes (e.g., "...qsf._fHello.!.a....")
 * @throws {RangeError} If length is negative.
 */
export function toAscii(bytes: Uint8Array, length: number = Infinity, placeholder: string = "."): string {
    const [lengthToDecode, ellipsis] = getDecodeBounds(bytes, length);
    const asciiArray = new Array(lengthToDecode);

    for (let i = 0; i < lengthToDecode; i++) {
        const byte = bytes[i];
        asciiArray[i] = isPrintable(byte) ? String.fromCharCode(byte) : placeholder;
    }

    return asciiArray.join("") + ellipsis;
}

/**
 * Fast bytes to hexadecimal and ASCII conversion.
 * @param bytes - Bytes to be decoded.
 * @param length - Number of bytes which will be decoded. Defaults to Infinity.
 * @param placeholder - Placeholder for ascii representation of not-printable bytes. Defaults to "."
 * @returns A tuple [hex, ascii] with the decoded representations.
 * @throws {RangeError} If length is negative.
 */
export function toHexAndAscii(
    bytes: Uint8Array,
    length: number = Infinity,
    placeholder: string = "."
): [string, string] {
    const [lengthToDecode, ellipsis] = getDecodeBounds(bytes, length);
    const hexArray = new Array(lengthToDecode);
    const asciiArray = new Array(lengthToDecode);

    for (let i = 0; i < lengthToDecode; i++) {
        const byte = bytes[i];
        hexArray[i] = HEX_TABLE[byte];
        asciiArray[i] = isPrintable(byte) ? String.fromCharCode(byte) : placeholder;
    }

    return ["0x" + hexArray.join("") + ellipsis, asciiArray.join("") + ellipsis];
}
