import crypto from 'crypto';

// Pass these fields to decipher 
const key = Buffer.from("4tmvsbJaVBQPFxsum+c3lA==", 'utf8'); // literal string bytes
const nonce = "Ft5MhFp5iMJMzGLaCWiTV5UxpK3gKGIz";
const associatedData = "JOYPAY";
const ciphertextBase64 = "m9maVw9vds55U4ZMp9b1T2QgNPmJalmYc2b3BgV2yJJzDskFdqnyP7zeweBosF90YJOaCtwi+R0Bdnu+YM1gST2/vgNWzvTiLxgtLsYvfoFjC7m8ZnLBqQ/uBwK3TOzV8XdJ/HTCv32A2ZLiW8URt4K+bu5fHQ7NNuiAyZ+tHuHziu3oHuEhDQWAtxWSeUDdAG9hA/1tgx1J1mMOz+j86hwNywhVy8wOUiQej3cUv8cAtqjxSLkQRYZsTNmyjC4Ktk+33sqaqcIW6EsvgoLIkARmuDUEM8SVzYpwcUnD6zE5kDFkIlI1k7BPihBQUm+wDHb7qg/6ajVrCjIElI0uN4ESqznS5AT9ZYpKulflIl2EcDQMUk4thAS+Y+gg5sw0hDzy2xYUO23CodwZBnxa8Q3k8yDFarVbk8rS9EnrMXHEDSrP/flLUhE3UnYHWczV7/AHbXa85V6uyyyqCV2WC1YR9ksJDS+ANOmRkSSqKes796N+SsQYQyQDdNlN25cHs70FGkxOZX/Af7WwViq2zp1HHrhCUhfNH4JIfpqddbYSE8MOkT99zUHe+WwXfvp3FRs0IOyijxxNYodRol+2hYgTh+DLIz4=";

try {
  // AES-192-GCM because key length is 24 bytes
  const decipher = crypto.createDecipheriv('aes-192-gcm', key, Buffer.from(nonce, 'utf8'));

  if (associatedData) {
    decipher.setAAD(Buffer.from(associatedData, 'utf8'));
  }

  const ciphertextBuffer = Buffer.from(ciphertextBase64, 'base64');
  const authTag = ciphertextBuffer.slice(ciphertextBuffer.length - 16);
  const encrypted = ciphertextBuffer.slice(0, ciphertextBuffer.length - 16);

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  console.log("✅ Decrypted:", decrypted.toString('utf8'));
} catch (err) {
  console.error("❌ Decryption failed:", err.message);
}
