package com.queryshield.eval;

/**
 * A confusion matrix and the rates derived from it, for one detector
 * configuration on one split.
 *
 * <p>Convention: the "positive" class is <em>attack</em>. So a true positive is
 * an attack we blocked; a false positive is a benign input we wrongly blocked.
 *
 * <p>Why these rates and not plain accuracy: the dataset is roughly balanced,
 * but in the real world benign traffic hugely outnumbers attacks, so accuracy
 * would be dominated by the benign class and look great even for a detector
 * that blocks nothing useful. Recall (did we catch attacks?) and the
 * false-positive rate (did we wrongly block real users?) are the numbers that
 * matter, and precision ties them together.
 */
public final class Metrics {

    private int tp; // attack, blocked
    private int fp; // benign, blocked
    private int tn; // benign, allowed
    private int fn; // attack, allowed

    public void record(boolean actualAttack, boolean blocked) {
        if (actualAttack) {
            if (blocked) {
                tp++;
            } else {
                fn++;
            }
        } else if (blocked) {
            fp++;
        } else {
            tn++;
        }
    }

    public int tp() {
        return tp;
    }

    public int fp() {
        return fp;
    }

    public int tn() {
        return tn;
    }

    public int fn() {
        return fn;
    }

    public int total() {
        return tp + fp + tn + fn;
    }

    /** Recall / detection rate: of all attacks, the fraction we blocked. */
    public double recall() {
        return ratio(tp, tp + fn);
    }

    /** False-positive rate: of all benign inputs, the fraction we blocked. */
    public double falsePositiveRate() {
        return ratio(fp, fp + tn);
    }

    /** Precision: of everything we blocked, the fraction that really was an attack. */
    public double precision() {
        return ratio(tp, tp + fp);
    }

    public double f1() {
        double p = precision();
        double r = recall();
        return (p + r == 0) ? 0 : 2 * p * r / (p + r);
    }

    public double accuracy() {
        return ratio(tp + tn, total());
    }

    private static double ratio(int num, int den) {
        return den == 0 ? 0.0 : (double) num / den;
    }
}
