package com.queryshield.detect;

import java.util.List;

/**
 * The detector's decision about one field value.
 *
 * @param block      whether the field should cause the request to be blocked
 * @param score      sum of the weights of everything that matched
 * @param normalized the normalized text the decision was made on (useful for
 *                   logging and debugging the "what did it actually see?")
 * @param findings   every signature/rule that contributed, with positions
 */
public record Verdict(boolean block, int score, String normalized, List<Finding> findings) {
}
