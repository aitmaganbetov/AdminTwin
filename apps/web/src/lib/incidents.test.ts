import { describe, expect, it } from "vitest";
import { splitFact } from "./incidents";

describe("splitFact (RCA evidence)", () => {
  it("separates the read tool from its output", () => {
    expect(splitFact('docker.container.inspect: {"container": "3f2a"}')).toEqual({
      tool: "docker.container.inspect",
      text: '{"container": "3f2a"}',
    });
  });
  it("keeps multi-line output intact", () => {
    expect(splitFact("logs.search: line 1\nline 2").text).toBe("line 1\nline 2");
  });
  it("leaves plain sentences untouched", () => {
    expect(splitFact("OOM: container killed")).toEqual({ tool: null, text: "OOM: container killed" });
    expect(splitFact("Disk at 96%")).toEqual({ tool: null, text: "Disk at 96%" });
  });
});
