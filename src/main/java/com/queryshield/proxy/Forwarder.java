package com.queryshield.proxy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Forwards a (clean) request to the upstream app and carries its response back.
 *
 * <p>Forwarding correctly is the part that must work before detection matters
 * at all: a proxy that mangles responses is useless no matter how good its
 * detector is. The fiddly bits, all handled here:
 *
 * <ul>
 *   <li><b>Hop-by-hop headers</b> (Connection, Keep-Alive, TE, Trailer,
 *       Transfer-Encoding, Upgrade, Proxy-*) describe a single connection and
 *       must not be relayed end to end -- RFC 7230. They are stripped both ways.
 *   <li><b>Restricted headers</b>: {@link HttpClient} refuses to let us set some
 *       request headers (Host, Content-Length, Connection, ...). We skip those
 *       and let the client set them correctly from the URI and body.
 *   <li><b>Framing</b>: we read the full upstream body, so we always know its
 *       length and send a clean Content-Length downstream. A chunked upstream is
 *       dechunked by the client and re-framed as fixed-length -- still correct
 *       HTTP. (Trade-off: the response is buffered, not streamed; fine for this
 *       app, noted as a limitation for large/streaming responses.)
 * </ul>
 */
public final class Forwarder {

    // Headers that are per-connection and must not be forwarded either way.
    private static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection");

    // Request headers HttpClient will not let us set; it sets them itself.
    private static final Set<String> RESTRICTED_REQUEST = Set.of(
            "connection", "content-length", "host", "upgrade", "http2-settings",
            "transfer-encoding", "keep-alive", "te", "trailer", "via", "expect");

    /** The upstream response, reduced to what we relay downstream. */
    public record Response(int status, Map<String, List<String>> headers, byte[] body) {
    }

    private final HttpClient client;
    private final URI upstreamBase;

    public Forwarder(URI upstreamBase) {
        this.upstreamBase = upstreamBase;
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER) // the client, not us, decides
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public Response forward(String method, String path, String rawQuery,
                            Map<String, List<String>> requestHeaders, byte[] body)
            throws Exception {

        String target = upstreamBase.toString() + path + (rawQuery == null ? "" : "?" + rawQuery);
        HttpRequest.BodyPublisher bodyPublisher = (body != null && body.length > 0)
                ? HttpRequest.BodyPublishers.ofByteArray(body)
                : HttpRequest.BodyPublishers.noBody();

        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(target))
                .method(method, bodyPublisher)
                .timeout(Duration.ofSeconds(30));

        for (Map.Entry<String, List<String>> e : requestHeaders.entrySet()) {
            String name = e.getKey().toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP.contains(name) || RESTRICTED_REQUEST.contains(name)) {
                continue;
            }
            for (String value : e.getValue()) {
                b.header(e.getKey(), value);
            }
        }

        HttpResponse<byte[]> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());

        // Strip hop-by-hop headers from the response; Content-Length is set from
        // the actual body when we write it downstream.
        var headers = new java.util.LinkedHashMap<String, List<String>>();
        resp.headers().map().forEach((name, values) -> {
            String lower = name.toLowerCase(Locale.ROOT);
            if (!HOP_BY_HOP.contains(lower) && !lower.equals("content-length")) {
                headers.put(name, values);
            }
        });

        return new Response(resp.statusCode(), headers, resp.body());
    }
}
