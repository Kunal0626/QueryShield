package com.queryshield.eval;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * A small closed-loop HTTP load generator used to measure the proxy's overhead.
 *
 * <p>Fixed thread count, a warm-up phase (discarded, so JIT compilation and
 * connection setup do not pollute the numbers), then a fixed measurement
 * window. It records every request's latency and reports throughput and the
 * p50/p95/p99 tail, for the same benign request sent two ways: straight to the
 * victim, and through the proxy. The difference is QueryShield's cost.
 *
 * <p><b>Honest caveat, printed with the results:</b> the victim and the proxy
 * run on the same machine over loopback, so there is essentially no network
 * latency to hide behind. That makes the <em>relative</em> overhead a pessimistic
 * view in one sense (every microsecond the proxy adds shows up) and the absolute
 * numbers specific to this machine. It is a lower bound on real-world absolute
 * latency, not a production benchmark.
 *
 * <p>Run via {@code make loadtest} (which starts the servers first).
 */
public final class LoadGen {

    private record Result(long requests, long errors, double seconds, long[] sortedLatenciesNanos) {
        double rps() {
            return seconds > 0 ? requests / seconds : 0;
        }

        double pctMs(double p) {
            if (sortedLatenciesNanos.length == 0) {
                return 0;
            }
            int idx = (int) Math.ceil(p / 100.0 * sortedLatenciesNanos.length) - 1;
            idx = Math.max(0, Math.min(idx, sortedLatenciesNanos.length - 1));
            return sortedLatenciesNanos[idx] / 1_000_000.0;
        }
    }

    public static void main(String[] args) throws Exception {
        String name = arg(args, "--name=", "proxy overhead");
        String direct = arg(args, "--direct=", "http://127.0.0.1:8081/search?q=mug");
        String proxy = arg(args, "--proxy=", "http://127.0.0.1:8080/search?q=mug");
        int threads = intArg(args, "--threads=", 16);
        int duration = intArg(args, "--duration=", 10);
        int warmup = intArg(args, "--warmup=", 3);

        System.out.println("## " + name + "\n");
        System.out.println("Closed-loop, " + threads + " threads, " + warmup
                + "s warm-up (discarded) + " + duration + "s measured, per scenario.\n");

        // Warm up both paths; results discarded.
        runScenario(direct, threads, warmup);
        runScenario(proxy, threads, warmup);

        Result rd = runScenario(direct, threads, duration);
        Result rp = runScenario(proxy, threads, duration);

        System.out.println("| scenario | requests | errors | req/s | p50 ms | p95 ms | p99 ms | max ms |");
        System.out.println("|----------|---------:|-------:|------:|-------:|-------:|-------:|-------:|");
        row("direct (victim)", rd);
        row("through proxy", rp);
        System.out.println();

        // Signed: a positive throughput change means the proxy was faster this
        // run (which happens when the backend dominates and the proxy's own cost
        // is below the run-to-run noise). Reported honestly either way.
        double throughputChange = rd.rps() > 0 ? (rp.rps() / rd.rps() - 1) * 100 : 0;
        System.out.printf("Throughput: direct %.0f req/s, proxy %.0f req/s (%+.1f%% through the proxy).%n",
                rd.rps(), rp.rps(), throughputChange);
        System.out.printf("Added latency through the proxy: p50 %+.2f ms, p99 %+.2f ms.%n",
                rp.pctMs(50) - rd.pctMs(50), rp.pctMs(99) - rd.pctMs(99));
        System.out.println();
    }

    private static void row(String label, Result r) {
        System.out.printf("| %s | %d | %d | %.0f | %.2f | %.2f | %.2f | %.2f |%n",
                label, r.requests(), r.errors(), r.rps(),
                r.pctMs(50), r.pctMs(95), r.pctMs(99), r.pctMs(100));
    }

    /** Drive {@code url} with {@code threads} workers for {@code seconds}. */
    private static Result runScenario(String url, int threads, int seconds) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .GET().timeout(Duration.ofSeconds(10)).build();

        long deadline = System.nanoTime() + seconds * 1_000_000_000L;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Worker>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> new Worker(client, req, deadline).run());
        }

        long start = System.nanoTime();
        List<Future<Worker>> futures = pool.invokeAll(tasks);
        pool.shutdown();
        double elapsed = (System.nanoTime() - start) / 1_000_000_000.0;

        List<Long> all = new ArrayList<>();
        long errors = 0;
        for (Future<Worker> f : futures) {
            Worker w = f.get();
            all.addAll(w.latencies);
            errors += w.errors;
        }
        long[] sorted = all.stream().mapToLong(Long::longValue).sorted().toArray();
        return new Result(sorted.length, errors, elapsed, sorted);
    }

    /** One worker: hammer the request until the deadline, recording latencies. */
    private static final class Worker {
        private final HttpClient client;
        private final HttpRequest req;
        private final long deadline;
        private final List<Long> latencies = new ArrayList<>();
        private long errors = 0;

        Worker(HttpClient client, HttpRequest req, long deadline) {
            this.client = client;
            this.req = req;
            this.deadline = deadline;
        }

        Worker run() {
            while (System.nanoTime() < deadline) {
                long t0 = System.nanoTime();
                try {
                    HttpResponse<Void> r = client.send(req, HttpResponse.BodyHandlers.discarding());
                    long t1 = System.nanoTime();
                    latencies.add(t1 - t0);
                    if (r.statusCode() >= 500) {
                        errors++;
                    }
                } catch (Exception e) {
                    errors++;
                }
            }
            return this;
        }
    }

    private static String arg(String[] args, String prefix, String def) {
        for (String a : args) {
            if (a.startsWith(prefix)) {
                return a.substring(prefix.length());
            }
        }
        return def;
    }

    private static int intArg(String[] args, String prefix, int def) {
        String v = arg(args, prefix, null);
        return v == null ? def : Integer.parseInt(v);
    }

    private LoadGen() {
    }
}
