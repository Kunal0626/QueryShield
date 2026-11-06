package com.queryshield.eval;

/** One labelled dataset row (see data/*.csv). */
public record Row(String id, String input, String label, String category, String split) {

    public boolean isAttack() {
        return "attack".equals(label);
    }

    public boolean isDev() {
        return "dev".equals(split);
    }

    public boolean isTest() {
        return "test".equals(split);
    }
}
