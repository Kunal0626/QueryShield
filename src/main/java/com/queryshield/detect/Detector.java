package com.queryshield.detect;

import com.queryshield.normalize.Normalized;
import com.queryshield.normalize.Normalizer;
import com.queryshield.rules.RuleEngine;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The detector: given one field value, decide whether it looks like SQL
 * injection. This is the single component shared by the offline evaluation
 * harness and the live proxy -- deliberately so, because every published number
 * must describe the same code that actually runs in front of the app. If the
 * harness used a different code path, the metrics would be about nothing.
 *
 * <p>What it does, controlled by {@link DetectorConfig}:
 * <ol>
 *   <li>normalize the input (v2/v3) or just lowercase it (v1);
 *   <li>scan for signatures with the Aho-Corasick automaton;
 *   <li>(Phase 6) run the tokenizer rules;
 *   <li>decide: block on any match, or on summed weight reaching a threshold.
 * </ol>
 */
public final class Detector {

    private final DetectorConfig config;
    private final Normalizer normalizer = new Normalizer();
    private final SignatureSet signatures;
    private final RuleEngine rules = new RuleEngine();

    public Detector(DetectorConfig config, SignatureSet signatures) {
        this.config = config;
        this.signatures = signatures;
    }

    public DetectorConfig config() {
        return config;
    }

    /**
     * Inspect one field value.
     *
     * @param field the field's name (query param, header, JSON key) -- carried
     *              for logging; it does not affect the decision
     * @param raw   the raw value exactly as received (still encoded)
     */
    public Verdict inspect(String field, String raw) {
        Normalized norm = null;
        String text;
        if (config.normalize()) {
            norm = normalizer.normalize(raw);
            text = norm.value();
        } else {
            // v1 baseline: the most naive preprocessing anyone would do.
            text = raw.toLowerCase(Locale.ROOT);
        }

        List<Finding> findings = new ArrayList<>(signatures.find(text, norm));
        if (config.useRules()) {
            findings.addAll(rules.apply(text, norm));
        }

        int score = 0;
        for (Finding f : findings) {
            score += f.weight();
        }

        boolean block = switch (config.decision()) {
            case ANY_MATCH -> !findings.isEmpty();
            case SCORE -> score >= config.threshold();
        };

        return new Verdict(block, score, text, findings);
    }
}
