/**
 * Utility functions for file hashing
 */

/**
 * Calculate SHA256 hash of a file
 * @param file - The file to hash
 * @returns Promise<string> - The SHA256 hash as a hex string
 */
export const calculateFileSHA256 = async (file: File): Promise<string> => {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
};

/**
 * Truncate long file names for display
 * @param fileName - The file name to truncate
 * @param maxLength - Maximum length before truncation (default: 20)
 * @returns string - Truncated file name with ellipsis if needed
 */
export const truncateFileName = (fileName: string, maxLength: number = 20): string => {
  if (fileName.length <= maxLength) {
    return fileName;
  }
  const extension = fileName.split('.').pop();
  const nameWithoutExt = fileName.substring(0, fileName.lastIndexOf('.'));
  const truncatedName = nameWithoutExt.substring(0, maxLength - 4) + '...';
  return extension ? `${truncatedName}.${extension}` : truncatedName;
};

/**
 * Format SHA256 hash for display (show first 8 and last 8 characters)
 * @param hash - The SHA256 hash
 * @returns string - Formatted hash for display
 */
export const formatSHA256ForDisplay = (hash: string): string => {
  if (hash.length <= 16) {
    return hash;
  }
  return `${hash.substring(0, 8)}...${hash.substring(hash.length - 8)}`;
};
