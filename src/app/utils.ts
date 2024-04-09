// Generate cryptographically safe random number between 0 and 1
export function rand(): number {
    if (window === undefined) {
        throw new Error('Must be run in browser context');
    }

    const arr = new Uint32Array(1);
    window.crypto.getRandomValues(arr);
    return arr[0] / (0xffffffff + 1);
}

// TODO:
// add utils for importing, wrapping, unwrapping, generating, etc. keys
