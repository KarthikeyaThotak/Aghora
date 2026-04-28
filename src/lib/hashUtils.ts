/**
 * Browser-native SHA-256 hashing utilities.
 * Uses the Web Crypto API — no external dependencies.
 */

/**
 * Compute the SHA-256 hash of a File object.
 * Returns the hex-encoded digest string.
 */
export async function calculateFileSHA256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Format a hex SHA-256 string into a readable display form.
 * Groups into 8-character blocks separated by spaces.
 * e.g. "aabbccdd eeffgghh ..."
 */
export function formatSHA256ForDisplay(hash: string): string {
  if (!hash) return "";
  return hash.match(/.{1,8}/g)?.join(" ") ?? hash;
}

/**
 * Truncate a file name to a maximum length, preserving the extension.
 * e.g. "very_long_malware_name.exe" → "very_long_malwa….exe"
 */
export function truncateFileName(name: string, maxLength = 20): string {
  if (!name || name.length <= maxLength) return name;
  const dotIndex = name.lastIndexOf(".");
  if (dotIndex > 0) {
    const ext  = name.slice(dotIndex);          // ".exe"
    const base = name.slice(0, dotIndex);       // stem
    const keep = maxLength - ext.length - 1;   // chars of stem to keep
    return keep > 0 ? `${base.slice(0, keep)}…${ext}` : `${name.slice(0, maxLength - 1)}…`;
  }
  return `${name.slice(0, maxLength - 1)}…`;
}
