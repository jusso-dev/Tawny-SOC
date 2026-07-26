export const MAX_THREAT_INTEL_VALUE_BYTES = 2048;

export function isIndexableThreatIntelValue(value: string): boolean {
  return (
    value.trim().length > 0 &&
    Buffer.byteLength(value, "utf8") <= MAX_THREAT_INTEL_VALUE_BYTES
  );
}
