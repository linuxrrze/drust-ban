// Random passwords for admins handing out temporary ones.
const ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generatePassword(length = 20): string {
  const out: string[] = [];
  const buf = new Uint8Array(1);
  // rejection sampling: no modulo bias
  const limit = 256 - (256 % ALPHABET.length);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) out.push(ALPHABET[buf[0] % ALPHABET.length]);
  }
  // groups of 5 are easier to read out
  return out.join('').replace(/(.{5})(?=.)/g, '$1-');
}

export const MIN_PASSWORD = 12;
