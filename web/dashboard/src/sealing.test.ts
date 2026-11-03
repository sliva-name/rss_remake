// @vitest-environment node
import { describe, expect, it } from "vitest";

import { type Binding, bindingAAD, sealPassword } from "./sealing";

const binding: Binding = {
  tenantId: "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f", agentId: "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e2a",
  engine: "postgresql", host: "db.example.invalid", port: 5432, database: "crm", username: "dg_scanner", tls: "verify-full",
};

// The agent's side, written independently of sealing.ts from the format description.
async function open(privateKey: CryptoKey, agentPublic: Uint8Array<ArrayBuffer>, target: Binding, sealed: Uint8Array<ArrayBuffer>) {
  const subtle = globalThis.crypto.subtle;
  expect(sealed[0]).toBe(1);
  const ephemeralBytes = sealed.slice(1, 66);
  const nonce = sealed.slice(66, 78);
  const ephemeral = await subtle.importKey("raw", ephemeralBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: ephemeral }, privateKey, 256);
  const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = new Uint8Array([...ephemeralBytes, ...agentPublic]);
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("dataguard sealed password v1") },
    material, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: bindingAAD(target) }, key, sealed.slice(78));
  return new TextDecoder().decode(plain);
}

describe("sealPassword", () => {
  it("opens only with the agent's key and only for its target", async () => {
    const subtle = globalThis.crypto.subtle;
    const agent = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
    const agentPublic = new Uint8Array(await subtle.exportKey("raw", agent.publicKey));
    const sealed = await sealPassword(agentPublic, binding, "synthetic-password");

    expect(sealed.length).toBe(1 + 65 + 12 + "synthetic-password".length + 16);
    expect(new TextDecoder().decode(sealed)).not.toContain("synthetic-password");
    await expect(open(agent.privateKey, agentPublic, binding, sealed)).resolves.toBe("synthetic-password");
    await expect(open(agent.privateKey, agentPublic, { ...binding, host: "attacker.example.invalid" }, sealed)).rejects.toThrow();
    await expect(open(agent.privateKey, agentPublic, { ...binding, tls: "disable" }, sealed)).rejects.toThrow();
  });

  it("refuses control characters that could shift the bound fields", () => {
    expect(() => bindingAAD({ ...binding, database: "crm\nadmin" })).toThrow();
  });
});
