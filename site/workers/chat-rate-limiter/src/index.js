const RATE_LIMIT = 15;
const RATE_WINDOW_MS = 60_000;
const WINDOW_KEY = 'window';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

export class ChatRateLimiter {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/check') {
      return json({ error: 'Not found' }, 404);
    }

    const now = Date.now();
    const decision = await this.state.storage.transaction(async () => {
      const current = await this.state.storage.get(WINDOW_KEY);
      if (!current || now >= current.resetAt) {
        const resetAt = now + RATE_WINDOW_MS;
        await this.state.storage.put(WINDOW_KEY, { count: 1, resetAt });
        return { allowed: true, retryAfterSeconds: 0, resetAt, newWindow: true };
      }

      if (current.count >= RATE_LIMIT) {
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
          resetAt: current.resetAt,
          newWindow: false,
        };
      }

      await this.state.storage.put(WINDOW_KEY, {
        count: current.count + 1,
        resetAt: current.resetAt,
      });
      return {
        allowed: true,
        retryAfterSeconds: 0,
        resetAt: current.resetAt,
        newWindow: false,
      };
    });

    if (decision.newWindow) {
      await this.state.storage.setAlarm(decision.resetAt);
    }
    return json({
      allowed: decision.allowed,
      retryAfterSeconds: decision.retryAfterSeconds,
    });
  }

  async alarm() {
    const now = Date.now();
    const nextAlarm = await this.state.storage.transaction(async () => {
      const current = await this.state.storage.get(WINDOW_KEY);
      if (!current) return null;
      if (now >= current.resetAt) {
        await this.state.storage.delete(WINDOW_KEY);
        return null;
      }
      return current.resetAt;
    });
    if (nextAlarm !== null) {
      await this.state.storage.setAlarm(nextAlarm);
    }
  }
}

// The Worker has no public API. Pages reaches ChatRateLimiter through a
// cross-script Durable Object namespace binding.
export default {
  fetch() {
    return json({ error: 'Not found' }, 404);
  },
};
