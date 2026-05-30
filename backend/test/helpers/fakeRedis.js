// Minimal in-memory Redis fake for tests. Implements just the commands the OTP
// store uses: set (with EX), get, ttl, del. TTLs are tracked as absolute expiry
// timestamps so ttl() returns a realistic countdown and expired keys read as
// absent. Inject via setRedisForTests() — no live Redis needed in unit tests.

export class FakeRedis {
  constructor() {
    this.store = new Map(); // key → { value, expiresAt|null }
  }

  #live(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && Date.now() >= entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry;
  }

  // set(key, value, 'EX', seconds)
  async set(key, value, mode, seconds) {
    let expiresAt = null;
    if (mode === 'EX' && Number.isFinite(seconds)) {
      expiresAt = Date.now() + seconds * 1000;
    }
    this.store.set(key, { value, expiresAt });
    return 'OK';
  }

  async get(key) {
    const entry = this.#live(key);
    return entry ? entry.value : null;
  }

  async ttl(key) {
    const entry = this.#live(key);
    if (!entry) return -2; // key doesn't exist (Redis semantics)
    if (entry.expiresAt === null) return -1; // exists, no expiry
    return Math.ceil((entry.expiresAt - Date.now()) / 1000);
  }

  async del(key) {
    return this.store.delete(key) ? 1 : 0;
  }

  // Test helper: force-expire a key's TTL to simulate timeouts.
  _expire(key) {
    this.store.delete(key);
  }

  _clear() {
    this.store.clear();
  }
}
