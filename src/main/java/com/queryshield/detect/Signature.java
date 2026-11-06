package com.queryshield.detect;

/**
 * One attack signature: a literal substring to look for, and a weight used by
 * the Phase 6 scoring detector (the v1/v2 detectors ignore the weight and block
 * on any match). Patterns are stored lowercase to match normalized input.
 */
public record Signature(String pattern, int weight) {
}
