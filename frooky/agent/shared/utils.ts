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