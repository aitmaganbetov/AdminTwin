import { describe, expect, it, vi } from "vitest";
import { openEventStream, SSEParser, type SSEMessage, type StreamState } from "./sse";

describe("SSEParser", () => {
  it("parses named events, multi-line data, ids and comments across chunk boundaries", () => {
    const p = new SSEParser();
    const out = [
      ...p.feed(": keep-alive\n"),
      ...p.feed("id: 1\nevent: tool_call\ndata: {\"tool\":"),
      ...p.feed("\"metrics.query\"}\n\n"),
      ...p.feed("event: fact\r\ndata: line1\r\ndata: line2\r\n\r"),
      ...p.feed("\n"),
      ...p.feed("data: plain\n\n"),
    ];
    expect(out).toEqual<SSEMessage[]>([
      { id: "1", event: "tool_call", data: '{"tool":"metrics.query"}' },
      { id: "1", event: "fact", data: "line1\nline2" },
      { id: "1", event: "message", data: "plain" },
    ]);
    expect(p.lastEventId).toBe("1");
  });

  it("reads retry and ignores events without data", () => {
    const p = new SSEParser();
    expect(p.feed("event: ping\n\n")).toEqual([]);
    const [m] = p.feed("retry: 2500\ndata: x\n\n");
    expect(m!.retry).toBe(2500);
  });
});

function streamResponse(chunks: string[]): Response {
  const enc = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      for (const ch of chunks) c.enqueue(enc.encode(ch));
      c.close();
    },
  });
  return new Response(body, { status: 200, headers: { "Content-Type": "text/event-stream" } });
}

describe("openEventStream (fetch reader)", () => {
  it("sends auth headers, delivers events and reconnects with Last-Event-ID", async () => {
    const calls: Record<string, string>[] = [];
    let n = 0;
    const f = vi.fn(async (_u: string | URL | Request, init?: RequestInit) => {
      calls.push(init!.headers as Record<string, string>);
      n++;
      if (n === 1) return streamResponse(["id: 7\nevent: hypothesis\ndata: {\"cause\":\"pool\"}\n\n"]);
      return streamResponse(["id: 8\nevent: cost\ndata: {\"provider\":\"claude\",\"cost_usd\":0.01}\n\n"]);
    });
    const msgs: SSEMessage[] = [];
    const states: StreamState[] = [];
    const h = openEventStream({
      url: "/api/v1/agent-tasks/t1/events",
      headers: { Authorization: "Bearer x" },
      fetchImpl: f as unknown as typeof fetch,
      retryMs: 5,
      onMessage: (m) => msgs.push(m),
      onState: (s) => states.push(s),
    });
    await vi.waitFor(() => expect(msgs.length).toBeGreaterThanOrEqual(2), { timeout: 2000 });
    h.close();
    expect(calls[0]!.Authorization).toBe("Bearer x");
    expect(calls[0]!.Accept).toBe("text/event-stream");
    expect(calls[1]!["Last-Event-ID"]).toBe("7");
    expect(msgs[0]!.event).toBe("hypothesis");
    expect(msgs[1]!.event).toBe("cost");
    expect(states).toContain("open");
    expect(states).toContain("reconnecting");
  });

  it("stops with 'unavailable' when the module route does not exist", async () => {
    const f = vi.fn(async () => new Response("404 page not found", { status: 404, headers: { "Content-Type": "text/plain" } }));
    const states: StreamState[] = [];
    openEventStream({ url: "/api/v1/agent-tasks/t/events", headers: { a: "b" }, fetchImpl: f as unknown as typeof fetch, onMessage: () => {}, onState: (s) => states.push(s) });
    await vi.waitFor(() => expect(states).toContain("unavailable"));
    expect(f).toHaveBeenCalledTimes(1);
  });
});
