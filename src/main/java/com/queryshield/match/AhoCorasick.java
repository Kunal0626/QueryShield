package com.queryshield.match;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Aho-Corasick multi-pattern string matcher, built from scratch.
 *
 * <p><b>The problem it solves.</b> We have many attack signatures (dozens to a
 * hundred) and want every occurrence of any of them in one request string. The
 * obvious approach -- loop over the patterns calling {@code text.contains(p)} --
 * costs O(N * (|text| * |pattern|)) and re-reads the text once per pattern.
 * Aho-Corasick reads the text <em>once</em>: after an O(sum of pattern lengths)
 * build, a scan is O(|text| + number of matches), independent of how many
 * patterns there are. That is the property that lets us add signatures freely
 * without slowing the proxy's hot path.
 *
 * <p><b>How it works.</b> The patterns form a trie (a prefix tree). Matching
 * walks the trie one input character at a time. When a character does not
 * continue the current branch, a <em>failure link</em> jumps to the longest
 * proper suffix of what we have matched so far that is still a prefix of some
 * pattern -- so we never re-examine input, the same idea as the KMP failure
 * function generalised to many patterns. <em>Output links</em> (dictionary
 * suffix links) let one position report every pattern that ends there, even
 * when patterns are suffixes of one another (matching "ushers" reports she,
 * he, hers).
 *
 * <p>This matcher is case-sensitive and works on {@code char} values; callers
 * normalize (lowercase, decode) before scanning. It is immutable after
 * {@link #build}, so one instance can be shared across threads for scanning.
 */
public final class AhoCorasick {

    /** One occurrence of a pattern: {@code text.substring(start, end)} equals it. */
    public record Match(String pattern, int start, int end) {
    }

    // Parallel to the node list; node 0 is always the root.
    private final List<Node> nodes;
    private final List<String> patterns; // patternId -> pattern text

    private AhoCorasick(List<Node> nodes, List<String> patterns) {
        this.nodes = nodes;
        this.patterns = patterns;
    }

    private static final class Node {
        // Trie edges by character. A HashMap keeps the alphabet open (Unicode)
        // without reserving a 65k-slot array per node.
        final Map<Character, Integer> next = new HashMap<>();
        int fail = 0;        // failure link (defaults to root)
        int outLink = -1;    // nearest suffix node that is itself a full pattern
        int patternId = -1;  // this node ends a pattern, or -1
        int depth = 0;       // distance from root = length of the string here
    }

    /**
     * Build an automaton for the given patterns. Empty patterns are ignored;
     * duplicates collapse to one. The returned matcher is immutable.
     */
    public static AhoCorasick build(Collection<String> rawPatterns) {
        // De-duplicate but keep a stable order so patternId is reproducible.
        Set<String> unique = new LinkedHashSet<>();
        for (String p : rawPatterns) {
            if (p != null && !p.isEmpty()) {
                unique.add(p);
            }
        }
        List<String> patterns = new ArrayList<>(unique);

        List<Node> nodes = new ArrayList<>();
        nodes.add(new Node()); // root

        // --- 1. Build the trie. -------------------------------------------
        for (int id = 0; id < patterns.size(); id++) {
            String p = patterns.get(id);
            int cur = 0;
            for (int i = 0; i < p.length(); i++) {
                char c = p.charAt(i);
                Integer nxt = nodes.get(cur).next.get(c);
                if (nxt == null) {
                    Node created = new Node();
                    created.depth = nodes.get(cur).depth + 1;
                    nxt = nodes.size();
                    nodes.add(created);
                    nodes.get(cur).next.put(c, nxt);
                }
                cur = nxt;
            }
            nodes.get(cur).patternId = id; // mark terminal
        }

        // --- 2. BFS to wire failure and output links. ---------------------
        // Depth-1 nodes fail to the root; deeper nodes fail to goto(fail(parent)).
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        Node root = nodes.get(0);
        for (int child : root.next.values()) {
            nodes.get(child).fail = 0;
            queue.add(child);
        }
        while (!queue.isEmpty()) {
            int u = queue.poll();
            Node node = nodes.get(u);
            for (Map.Entry<Character, Integer> e : node.next.entrySet()) {
                char c = e.getKey();
                int v = e.getValue();
                // Failure link of v: from u's failure node, follow the same char,
                // falling back through failure links until root or a match.
                int f = node.fail;
                while (f != 0 && !nodes.get(f).next.containsKey(c)) {
                    f = nodes.get(f).fail;
                }
                Integer target = nodes.get(f).next.get(c);
                nodes.get(v).fail = (target != null && target != v) ? target : 0;

                // Output link: the failure node if it ends a pattern, else that
                // node's own output link. This threads a chain of all patterns
                // that are suffixes ending here.
                int fv = nodes.get(v).fail;
                nodes.get(v).outLink = nodes.get(fv).patternId != -1 ? fv : nodes.get(fv).outLink;

                queue.add(v);
            }
        }

        return new AhoCorasick(nodes, patterns);
    }

    /**
     * Scan {@code text} and return every occurrence of every pattern, in the
     * order their end positions are reached. O(|text| + matches).
     */
    public List<Match> scan(String text) {
        List<Match> out = new ArrayList<>();
        int state = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            state = step(state, c);
            // Emit a match for this node if it is a terminal, then walk the
            // output-link chain for shorter patterns that also end here.
            Node s = nodes.get(state);
            if (s.patternId != -1) {
                emit(out, s.patternId, i);
            }
            int link = s.outLink;
            while (link != -1) {
                Node ln = nodes.get(link);
                emit(out, ln.patternId, i);
                link = ln.outLink;
            }
        }
        return out;
    }

    /** Transition from {@code state} on character {@code c}, using failure links. */
    private int step(int state, char c) {
        while (state != 0 && !nodes.get(state).next.containsKey(c)) {
            state = nodes.get(state).fail;
        }
        Integer nxt = nodes.get(state).next.get(c);
        return nxt != null ? nxt : 0;
    }

    private void emit(List<Match> out, int patternId, int endIndexInclusive) {
        String p = patterns.get(patternId);
        int end = endIndexInclusive + 1;
        out.add(new Match(p, end - p.length(), end));
    }

    /** Number of distinct patterns the automaton holds (for tests/metrics). */
    public int patternCount() {
        return patterns.size();
    }

    /** Number of trie nodes (for tests/metrics). */
    public int nodeCount() {
        return nodes.size();
    }
}
