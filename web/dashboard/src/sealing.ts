// Seals a database password in the browser so that only the chosen agent can open
// it, and only for this target. Same format as internal/platform/sealing in Go:
// 0x01 | ephemeral P-256 point (65) | nonce (12) | AES-256-GCM ciphertext and tag.

export type Binding = {
  tenantId: string;
  agentId: string;
  engine: string;
  host: string;
  port: number;
  database: string;
  username: string;
  tls: string;
};

const info = "dataguard sealed password v1";
const aadPrefix = "dataguard-sealed-password-v1";
const encoder = new TextEncoder();

export function bindingAAD(binding: Binding): Uint8Array<ArrayBuffer> {
  const fields = [
    aadPrefix, binding.tenantId, binding.agentId, binding.engine, binding.host,
    String(binding.port), binding.database, binding.username, binding.tls,
  ];
  // Fields are joined by newlines, so a control character could shift them.
  if (fields.some((field) => /\p{Cc}/u.test(field))) {
    throw new Error("control character in connection settings");
  }
  return encoder.encode(fields.join("\n"));
}

export async function sealPassword(agentPublicKey: Uint8Array<ArrayBuffer>, binding: Binding, password: string): Promise<Uint8Array<ArrayBuffer>> {
  const subtle = globalThis.crypto.subtle;
  const curve = { name: "ECDH", namedCurve: "P-256" };
  const recipient = await subtle.importKey("raw", agentPublicKey, curve, false, []);
  const ephemeral = (await subtle.generateKey(curve, true, ["deriveBits"])) as CryptoKeyPair;
  const ephemeralPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
  const shared = await subtle.deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256);
  const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = new Uint8Array(ephemeralPublic.length + agentPublicKey.length);
  salt.set(ephemeralPublic);
  salt.set(agentPublicKey, ephemeralPublic.length);
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(info) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: bindingAAD(binding) }, key, encoder.encode(password)),
  );
  const sealed = new Uint8Array(1 + ephemeralPublic.length + nonce.length + ciphertext.length);
  sealed[0] = 1;
  sealed.set(ephemeralPublic, 1);
  sealed.set(nonce, 1 + ephemeralPublic.length);
  sealed.set(ciphertext, 1 + ephemeralPublic.length + nonce.length);
  return sealed;
}

export function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

export function fromBase64(encoded: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
}
