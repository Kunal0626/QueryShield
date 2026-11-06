package com.queryshield.detect;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Behaviour tests for the detector. The dataset-wide numbers live in the eval
 * harness; these pin down specific, explainable decisions -- including the one
 * case that is the whole reason the normalizer exists.
 */
class DetectorTest {

    private SignatureSet sigs;

    @BeforeEach
    void load() {
        sigs = SignatureSet.fromResource("/signatures.txt");
    }

    private boolean blocks(DetectorConfig cfg, String input) {
        return new Detector(cfg, sigs).inspect("input", input).block();
    }

    @Test
    void signaturesLoaded() {
        assertTrue(sigs.size() >= 50, "expected the bundled signatures to load");
    }

    @Test
    void blocksPlainUnionSelect() {
        assertTrue(blocks(DetectorConfig.v2(), "' UNION SELECT username, password FROM users -- "));
    }

    @Test
    @DisplayName("the normalizer is why v2 catches an encoded payload that v1 misses")
    void normalizerCatchesEncodedPayload() {
        String encoded = "%55NION%20%53ELECT%201,2"; // percent-encoded UNION SELECT
        assertFalse(blocks(DetectorConfig.v1(), encoded), "v1 only lowercases, so it should miss this");
        assertTrue(blocks(DetectorConfig.v2(), encoded), "v2 decodes first, so it should catch it");
    }

    @Test
    void allowsApostropheName() {
        assertFalse(blocks(DetectorConfig.v2(), "O'Brien"));
        assertFalse(blocks(DetectorConfig.v2(), "Levi's jeans"));
    }

    @Test
    void allowsKeywordInProse() {
        assertFalse(blocks(DetectorConfig.v2(), "union station timetable"));
        assertFalse(blocks(DetectorConfig.v2(), "please order by phone"));
    }

    @Test
    void verdictCarriesFindingsAndScore() {
        Verdict v = new Detector(DetectorConfig.v2(), sigs)
                .inspect("q", "' OR 1=1 -- ");
        assertTrue(v.block());
        assertTrue(v.score() > 0);
        assertFalse(v.findings().isEmpty());
    }
}
