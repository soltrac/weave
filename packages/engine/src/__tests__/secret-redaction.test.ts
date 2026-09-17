import { describe, expect, it } from "bun:test";
import { redactSecrets } from "../runtime/secret-redaction.js";

// Synthetic fixture: OpenRouter-shaped key, not a real credential.
const OPENROUTER_KEY = "sk-or-v1-abcdef0123456789abcdef0123456789";
// Synthetic fixture: Anthropic-shaped key, not a real credential.
const ANTHROPIC_KEY = "sk-ant-abcdef0123456789abcdef0123456789";
// Synthetic fixture: GitHub PAT-shaped token, not a real credential.
const GITHUB_PAT = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

describe("redactSecrets", () => {
  it("redacts an OpenRouter sk-or-v1- style key", () => {
    const raw = `OPENROUTER_API_KEY=${OPENROUTER_KEY}`;
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain(OPENROUTER_KEY);
    expect(redacted).toContain("[REDACTED-KEY]");
  });

  it("redacts a Bearer authorization header", () => {
    const raw = `Authorization: Bearer ${OPENROUTER_KEY}`;
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain(OPENROUTER_KEY);
    expect(redacted).toContain("[REDACTED");
  });

  it("redacts a GitHub personal access token (ghp_...)", () => {
    const raw = `github_token=${GITHUB_PAT}`;
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain(GITHUB_PAT);
    expect(redacted).toContain("[REDACTED-KEY]");
  });

  it("redacts an Anthropic sk-ant- style key", () => {
    const raw = ANTHROPIC_KEY;
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain(ANTHROPIC_KEY);
    expect(redacted).toContain("[REDACTED-KEY]");
  });

  it("redacts a bare 32+ char hex blob", () => {
    const raw = "session=abcdef0123456789abcdef0123456789abcdef";
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain("abcdef0123456789abcdef0123456789abcdef");
    expect(redacted).toContain("[REDACTED-HEX]");
  });

  it("redacts an api_key query string parameter", () => {
    const raw = "https://example.com/v1?api_key=abcd1234secretvalue";
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain("abcd1234secretvalue");
    expect(redacted).toContain("[REDACTED]");
  });

  it("truncates when maxChars is provided", () => {
    const raw = "x".repeat(1000);
    const redacted = redactSecrets(raw, 100);
    expect(redacted.length).toBeLessThanOrEqual(120);
    expect(redacted).toContain("[truncated]");
  });

  it("leaves ordinary log content untouched", () => {
    const raw = "level=INFO message=created id=ses_parent slug=x";
    expect(redactSecrets(raw)).toBe(raw);
  });

  it("redacts multiple distinct secrets in one blob (realistic DEBUG stream)", () => {
    const raw =
      `headers.authorization="Bearer ${OPENROUTER_KEY}" ` +
      `openrouter_key=${OPENROUTER_KEY} ` +
      `github_token=${GITHUB_PAT}`;
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain(OPENROUTER_KEY);
    expect(redacted).not.toContain(GITHUB_PAT);
  });
});
