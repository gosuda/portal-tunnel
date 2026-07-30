import { describe, expect, it } from "vitest";

import { classifyShareInput } from "@/lib/shareLink";

describe("classifyShareInput", () => {
  it("treats bare ports and host:port as port shares", () => {
    expect(classifyShareInput("3000")).toMatchObject({
      kind: "port",
      target: "3000",
    });
    expect(classifyShareInput("localhost:8080")).toMatchObject({
      kind: "port",
      target: "localhost:8080",
    });
  });

  it("extracts host:port from http(s) URLs", () => {
    expect(classifyShareInput("http://localhost:3000/x")).toMatchObject({
      kind: "url",
      target: "localhost:3000",
    });
    expect(classifyShareInput("https://example.com")).toMatchObject({
      kind: "url",
      target: "example.com",
    });
  });

  it("resolves file:// URLs to filesystem paths", () => {
    expect(classifyShareInput("file:///Users/me/site/main.html")).toMatchObject({
      kind: "file",
      path: "/Users/me/site/main.html",
    });
    expect(
      classifyShareInput("file:///C:/Users/me/site/main.html")
    ).toMatchObject({
      kind: "file",
      path: "C:/Users/me/site/main.html",
    });
  });

  it("treats Windows, UNC, and absolute POSIX paths as file shares", () => {
    expect(classifyShareInput("C:\\Users\\me\\site\\main.html")).toMatchObject({
      kind: "file",
      path: "C:\\Users\\me\\site\\main.html",
    });
    expect(classifyShareInput("\\\\host\\share\\index.html")).toMatchObject({
      kind: "file",
      path: "\\\\host\\share\\index.html",
    });
    expect(classifyShareInput("/Users/me/site")).toMatchObject({
      kind: "file",
      path: "/Users/me/site",
    });
  });

  it("treats empty input as a port share", () => {
    expect(classifyShareInput("   ")).toMatchObject({ kind: "port", target: "" });
  });
});
