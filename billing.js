// Paid plans, through Paddle (merchant of record). Switched off unless BILLING=on.
//
// What stays true (docs/billing.md):
//   - checking a record never touches any of this;
//   - a plan belongs to a holder key, as records do; there is no account or password;
//   - stopping payment never breaks a record: only adding records past the free number stops;
//   - the registry keeps no name, email, address, card or amount (Paddle holds those);
//   - Paddle never sees a holder key. It sees a billing id: 32 random bytes the registry puts
//     on the checkout itself, meaningless outside this registry, and never shown to anyone.
//     A holder key is the holder's only credential (x-holder-key), so handing one to a
//     payment company would let it act as them;
//   - no Paddle code runs on VeilCore's site. The registry opens the checkout with Paddle's
//     API (POST /transactions, the billing id in custom_data) and the site sends the holder
//     to Paddle's own hosted checkout page with that transaction. The page that holds a
//     holder's keys never loads a payment company's script.
//
// Off, recordCapFor returns the same ceiling for everyone that the registry has always had,
// and every billing route answers 404, so a deploy with this file changes nothing.
//
// SPDX-License-Identifier: Apache-2.0

const { createHash, createHmac, randomBytes, timingSafeEqual } = require('node:crypto');

/** How old a webhook's signed timestamp may be. Paddle's default is 5 s; a restart can hold a
 *  delivery longer, and replay is stopped by the event id, so 5 minutes. */
const SIGNATURE_TOLERANCE_MS = 5 * 60_000;
/** Paid access continues this long after a period ends unpaid, so a late webhook or a card
 *  retry never cuts anyone off on the day. */
const GRACE_MS = 7 * 86_400_000;
/** How long an event id is kept to refuse a replay. Paddle retries for a few days. */
const EVENT_KEEP_MS = 30 * 86_400_000;
/** Statuses that count as paid whatever the date. */
const PAID_NOW = new Set(['active', 'trialing']);
/** Statuses that count as paid until the period ends, plus the grace. */
const PAID_UNTIL_END = new Set(['canceled', 'paused']);
/** A renewal that failed: paid for the grace only, counted from when it first failed. Paddle
 *  moves the period on when a renewal fails, so its period end would be a month unpaid. */
const PAST_DUE = 'past_due';
const STATUSES = new Set([...PAID_NOW, ...PAID_UNTIL_END, PAST_DUE]);
const EVENT_TYPES = new Set([
  'subscription.created',
  'subscription.activated',
  'subscription.updated',
  'subscription.canceled',
  'subscription.past_due',
  'subscription.paused',
  'subscription.resumed',
  'subscription.trialing',
]);
const BILLING_ID = /^[0-9a-f]{64}$/;
/** Billing ids kept per holder; older ones stop working, but never before BILLING_ID_MIN_AGE_MS,
 *  so a checkout someone is still paying for always lands. */
const BILLING_IDS_KEPT = 20;
const BILLING_ID_MIN_AGE_MS = 7 * 86_400_000;
/** Holders and addresses tracked for the checkout limits in one hour. Past it, new ones wait
 *  for the next hour: flooding with fresh keys can't reset anyone's count. */
const CHECKOUT_TRACKED_PER_HOUR = 50_000;
const PADDLE_ID = /^[a-z]{2,4}_[0-9a-z]{10,64}$/;
/** Paddle's two API hosts. A sandbox key works only on the sandbox one, and the reverse. */
const PADDLE_API = { sandbox: 'https://sandbox-api.paddle.com', live: 'https://api.paddle.com' };
/** A hosted checkout link: https://…paddle.io/checkout/hsc_… (set up in Paddle's dashboard). */
const HOSTED_CHECKOUT = /^https:\/\/([a-z-]+\.)?paddle\.io\/checkout\/hsc_[0-9a-z]{10,64}$/;
/** Checkouts Paddle opened, per holder and per address, in an hour: each one is a transaction
 *  in Paddle. Attempts (Paddle refusing or down included) are limited more loosely, so an
 *  outage doesn't use up anyone's checkouts but nobody can make billing ids without end. */
const CHECKOUTS_PER_HOUR = 10;
const CHECKOUTS_PER_HOUR_PER_IP = 20;
const ATTEMPTS_PER_HOUR = 30;
const ATTEMPTS_PER_HOUR_PER_IP = 60;

const digest = (s) => createHash('sha256').update(`veilcore:billing-id:v1:${s}`).digest('hex');
/** A record id as kept in billing_free_corrections: digested, so the table names no record. */
const idDigest = (id) => createHash('sha256').update(`veilcore:billing-counted:v1:${id}`).digest('hex');
/** A dated proof code as kept in billing_counted: digested, so the table holds no proof code. */
const fpDigest = (fp) => createHash('sha256').update(`veilcore:billing-dated:v1:${fp}`).digest('hex');

/**
 * Read the billing settings from the environment. Anything malformed switches billing off
 * with a reason, rather than starting half configured.
 */
const billingConfig = (env, hardCap) => {
  if (env.BILLING !== 'on') return { enabled: false, reason: `BILLING is "${String(env.BILLING ?? '')}", not "on"` };
  const secret = env.BILLING_PADDLE_WEBHOOK_SECRET ?? '';
  if (secret.length < 16) return { enabled: false, reason: 'BILLING_PADDLE_WEBHOOK_SECRET is missing' };
  const freeText = env.BILLING_FREE_RECORDS ?? '';
  const free = /^\d{1,6}$/.test(freeText) ? Number(freeText) : NaN;
  if (!Number.isInteger(free) || free > hardCap) {
    return { enabled: false, reason: 'BILLING_FREE_RECORDS must be a whole number' };
  }
  const prices = new Map();
  for (const pair of (env.BILLING_PADDLE_PRICES ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const [price, plan] = pair.split('=').map((s) => s.trim());
    if (!PADDLE_ID.test(price ?? '') || !/^[a-z]{2,20}$/.test(plan ?? '')) {
      return { enabled: false, reason: `BILLING_PADDLE_PRICES entry "${pair}" is not price_id=plan` };
    }
    prices.set(price, plan);
  }
  if (!prices.size) return { enabled: false, reason: 'BILLING_PADDLE_PRICES is empty' };
  if (new Set(prices.values()).size !== prices.size) {
    return { enabled: false, reason: 'BILLING_PADDLE_PRICES names a plan twice' };
  }
  const api = env.BILLING_PADDLE_API ?? '';
  if (!Object.values(PADDLE_API).includes(api)) {
    return { enabled: false, reason: `BILLING_PADDLE_API must be ${PADDLE_API.sandbox} or ${PADDLE_API.live}` };
  }
  const apiKey = env.BILLING_PADDLE_API_KEY ?? '';
  if (apiKey.length < 20) return { enabled: false, reason: 'BILLING_PADDLE_API_KEY is missing' };
  if ((api === PADDLE_API.sandbox) !== apiKey.includes('_sdbx')) {
    return { enabled: false, reason: 'BILLING_PADDLE_API_KEY and BILLING_PADDLE_API are not both sandbox or both live' };
  }
  const checkout = env.BILLING_PADDLE_CHECKOUT ?? '';
  if (!HOSTED_CHECKOUT.test(checkout)) {
    return { enabled: false, reason: 'BILLING_PADDLE_CHECKOUT must be a hosted checkout link (https://…paddle.io/checkout/hsc_…)' };
  }
  const priceOfPlan = new Map([...prices].map(([price, plan]) => [plan, price]));
  return { enabled: true, secret, free, prices, priceOfPlan, api, apiKey, checkout };
};

/**
 * Check a Paddle-Signature header ("ts=...;h1=...", h1 possibly repeated while a secret is
 * rotated) over the raw body. True only for a fresh timestamp and a matching h1.
 */
const signatureOk = (header, raw, secret, now) => {
  if (typeof header !== 'string' || !Buffer.isBuffer(raw)) return false;
  let ts;
  const h1 = [];
  for (const part of header.split(';')) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    const k = part.slice(0, at).trim();
    const v = part.slice(at + 1).trim();
    if (k === 'ts') ts = v;
    else if (k === 'h1') h1.push(v);
  }
  if (!ts || !/^\d{1,12}$/.test(ts) || !h1.length) return false;
  if (Math.abs(now - Number(ts) * 1000) > SIGNATURE_TOLERANCE_MS) return false;
  const want = createHmac('sha256', secret).update(`${ts}:`).update(raw).digest();
  return h1.some((h) => {
    if (!/^[0-9a-f]{64}$/i.test(h)) return false;
    return timingSafeEqual(want, Buffer.from(h, 'hex'));
  });
};

/**
 * @param db better-sqlite3 database
 * @param opts.env process.env or a stand-in
 * @param opts.hardCap the registry's ceiling for everyone (MAX_PER_HOLDER)
 * @param opts.now clock, for tests
 */
const createBilling = (
  db,
  { env = process.env, hardCap, now = () => Date.now(), fetchImpl = (...a) => globalThis.fetch(...a) } = {},
) => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS billing_ids (
      id_digest TEXT PRIMARY KEY,
      holder_key TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS billing_ids_holder ON billing_ids(holder_key, created_at);
    CREATE TABLE IF NOT EXISTS billing_plans (
      subscription_id TEXT PRIMARY KEY,
      holder_key TEXT NOT NULL,
      plan TEXT NOT NULL,
      status TEXT NOT NULL,
      period_end INTEGER,
      past_due_since INTEGER,
      paid_through INTEGER,
      occurred_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS billing_plans_holder ON billing_plans(holder_key);
    CREATE TABLE IF NOT EXISTS billing_events (
      event_id TEXT PRIMARY KEY,
      received_at INTEGER NOT NULL
    );
    -- Holders above the free number when billing is switched on keep what they hold and may add
    -- the free number again, for good: nobody is cut off by a change they didn't choose. Done
    -- each time billing goes from off to on; a cap is only ever raised.
    -- Not unique on holder_key: the holder-key migration (holder-key.js) moves rows from an
    -- old key form to the new one, and two forms of one key may each have a row.
    CREATE TABLE IF NOT EXISTS billing_grandfathered (
      holder_key TEXT NOT NULL,
      cap INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS billing_grandfathered_holder ON billing_grandfathered(holder_key);
    -- The proof codes that count against the free plan: one row per distinct proof code this
    -- holder had dated (digested), never removed. The free plan limits dates made, not records
    -- kept: deleting doesn't make room, the same content saved again doesn't count twice, and
    -- new content under an old id counts. A record's one correction is not counted.
    CREATE TABLE IF NOT EXISTS billing_counted (
      holder_key TEXT NOT NULL,
      id_digest TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS billing_counted_holder ON billing_counted(holder_key, id_digest);
    -- Records whose one free correction was used: a correction deleted and made again counts.
    CREATE TABLE IF NOT EXISTS billing_free_corrections (
      holder_key TEXT NOT NULL,
      target_digest TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS billing_free_corrections_holder ON billing_free_corrections(holder_key, target_digest);
    CREATE TABLE IF NOT EXISTS billing_meta (
      k TEXT PRIMARY KEY,
      v TEXT NOT NULL
    );
  `);
  const config = billingConfig(env, hardCap);
  if (!config.enabled && (env.BILLING ?? '') !== '') console.error(`billing stays off: ${config.reason}`);

  // Added before paid_through existed (a sandbox database): the column is added in place.
  if (!db.prepare("SELECT 1 FROM pragma_table_info('billing_plans') WHERE name = 'paid_through'").get()) {
    db.exec('ALTER TABLE billing_plans ADD COLUMN paid_through INTEGER');
  }

  // What counts: every proof code a holder holds (received deliveries too, once they sealed
  // their own content), less a record's one correction: a row correcting a record of the same
  // holder that is neither a correction nor received.
  const FREE_CORRECTION = `EXISTS (
    SELECT 1 FROM records t WHERE t.id = json_extract(r.body, '$.supersedes.recordId')
      AND t.holder_key = r.holder_key AND json_extract(t.body, '$.supersedes') IS NULL
      AND json_extract(t.body, '$.receivedFrom') IS NULL)`;
  const COUNTS = `json_extract(r.body, '$.recordFingerprint') IS NOT NULL AND NOT ${FREE_CORRECTION}`;
  // Counted by record id before 17 Nov (sandbox only): those rows are dropped and re-seeded.
  const byFingerprint = db.prepare("SELECT v FROM billing_meta WHERE k = 'counted_by'").get()?.v === 'fingerprint';
  if (!byFingerprint) {
    db.exec('DELETE FROM billing_counted');
    db.prepare("INSERT INTO billing_meta (k, v) VALUES ('counted_by', 'fingerprint') ON CONFLICT(k) DO UPDATE SET v = excluded.v").run();
  }
  const wasOn = byFingerprint && db.prepare("SELECT v FROM billing_meta WHERE k = 'last_start'").get()?.v === 'on';
  if (config.enabled && !wasOn) {
    // Switched on (first time, or again after a spell off): grandfather from what each holder
    // holds that counts, and count every such record not counted yet. A cap is only raised.
    db.transaction(() => {
      db.prepare(
        `INSERT INTO billing_grandfathered (holder_key, cap)
         SELECT r.holder_key, COUNT(DISTINCT json_extract(r.body, '$.recordFingerprint')) + ? FROM records r WHERE ${COUNTS}
         GROUP BY r.holder_key HAVING COUNT(DISTINCT json_extract(r.body, '$.recordFingerprint')) > ?`,
      ).run(config.free, config.free);
      const add = db.prepare(
        `INSERT INTO billing_counted (holder_key, id_digest) SELECT ?, ?
         WHERE NOT EXISTS (SELECT 1 FROM billing_counted WHERE holder_key = ? AND id_digest = ?)`,
      );
      for (const r of db.prepare(`SELECT json_extract(r.body, '$.recordFingerprint') AS fp, r.holder_key FROM records r WHERE ${COUNTS}`).all()) {
        const d = fpDigest(r.fp);
        add.run(r.holder_key, d, r.holder_key, d);
      }
      // The free corrections already made are used.
      const used = db.prepare(
        `INSERT INTO billing_free_corrections (holder_key, target_digest) SELECT ?, ?
         WHERE NOT EXISTS (SELECT 1 FROM billing_free_corrections WHERE holder_key = ? AND target_digest = ?)`,
      );
      for (const r of db.prepare(`SELECT r.holder_key, json_extract(r.body, '$.supersedes.recordId') AS target
                                  FROM records r WHERE ${FREE_CORRECTION}`).all()) {
        const d = idDigest(r.target);
        used.run(r.holder_key, d, r.holder_key, d);
      }
    })();
  }
  db.prepare("INSERT INTO billing_meta (k, v) VALUES ('last_start', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(
    config.enabled ? 'on' : 'off',
  );

  const plansOf = db.prepare(
    'SELECT plan, status, period_end, past_due_since, paid_through FROM billing_plans WHERE holder_key = ?',
  );
  const grandfatheredOf = db.prepare('SELECT MAX(cap) AS cap FROM billing_grandfathered WHERE holder_key = ?');
  const countedOf = db.prepare('SELECT COUNT(DISTINCT id_digest) AS n FROM billing_counted WHERE holder_key = ?');
  const isCounted = db.prepare('SELECT 1 FROM billing_counted WHERE holder_key = ? AND id_digest = ? LIMIT 1');
  const addCounted = db.prepare('INSERT INTO billing_counted (holder_key, id_digest) VALUES (?, ?)');
  const dropCounted = db.prepare('DELETE FROM billing_counted WHERE holder_key = ? AND id_digest = ?');
  const freeUsed = db.prepare('SELECT 1 FROM billing_free_corrections WHERE holder_key = ? AND target_digest = ? LIMIT 1');
  const addFreeUsed = db.prepare('INSERT INTO billing_free_corrections (holder_key, target_digest) VALUES (?, ?)');

  /** The best plan this holder has right now, or null. */
  const currentPlan = (holder) => {
    const t = now();
    let best = null;
    for (const p of plansOf.all(holder)) {
      // Cancelled or paused after a failed renewal: Paddle had already moved the period on, so
      // paid only to the end of the period that was paid for, and never past the grace.
      const until = p.past_due_since
        ? Math.min((p.paid_through ?? p.period_end ?? 0) + GRACE_MS, p.past_due_since + GRACE_MS)
        : (p.period_end ?? 0) + GRACE_MS;
      const paid =
        PAID_NOW.has(p.status) ||
        (PAID_UNTIL_END.has(p.status) && p.period_end && t < until) ||
        (p.status === PAST_DUE && p.past_due_since && t < p.past_due_since + GRACE_MS);
      if (paid && (!best || (p.period_end ?? Infinity) > (best.periodEnd ?? 0))) {
        best = { plan: p.plan, status: p.status, periodEnd: p.period_end ?? null };
      }
    }
    return best;
  };

  /** How many records this holder may keep. Off: the same for everyone, as always. */
  const recordCapFor = (holder) => {
    if (!config.enabled) return hardCap;
    if (currentPlan(holder)) return hardCap;
    const g = grandfatheredOf.get(holder);
    return Math.min(hardCap, Math.max(config.free, g?.cap ?? 0));
  };

  /** Proof codes that count against the free plan (billing_counted): deleted records' included. */
  const usedOf = (holder) => countedOf.get(holder).n;

  /**
   * How many more counted records this holder may add on their plan now: Infinity when billing
   * is off or the plan is paid (the registry's own ceiling still applies, by records held).
   * Returns { room, cap } so a refusal can say which ceiling it was.
   */
  const planRoom = (holder) => {
    if (!config.enabled || currentPlan(holder)) return { room: Infinity, cap: hardCap };
    const cap = recordCapFor(holder);
    return { room: Math.max(0, cap - usedOf(holder)), cap };
  };

  /** Whether this proof code already counted for this holder (dated before, maybe deleted since). */
  const wasCounted = (holder, fp) => !!isCounted.get(holder, fpDigest(fp));

  /** Count proof codes just stored or dated (call inside the transaction that wrote them). Each once. */
  const noteAdded = (holder, fps) => {
    if (!config.enabled) return;
    for (const fp of fps) if (typeof fp === 'string' && fp && !wasCounted(holder, fp)) addCounted.run(holder, fpDigest(fp));
  };

  /** Whether this record's one free correction is still to be used. Off: always (nothing counts). */
  const correctionIsFree = (holder, target) => !config.enabled || !freeUsed.get(holder, idDigest(target));
  /** The free correction of this record was used (call inside the transaction that stored it). */
  const noteFreeCorrection = (holder, target) => {
    if (config.enabled && correctionIsFree(holder, target)) addFreeUsed.run(holder, idDigest(target));
  };

  /** A proof code counted when only it was dated, now stored as a free correction. */
  const uncount = (holder, fp) => {
    if (config.enabled && typeof fp === 'string') dropCounted.run(holder, fpDigest(fp));
  };

  const pruneIds = db.prepare(
    `DELETE FROM billing_ids WHERE holder_key = ? AND created_at < ? AND id_digest NOT IN (
       SELECT id_digest FROM billing_ids WHERE holder_key = ? ORDER BY created_at DESC LIMIT ?)`,
  );
  const insertId = db.prepare('INSERT INTO billing_ids (id_digest, holder_key, created_at) VALUES (?, ?, ?)');
  const holderOfId = db.prepare('SELECT holder_key FROM billing_ids WHERE id_digest = ?');
  const seenEvent = db.prepare('SELECT 1 FROM billing_events WHERE event_id = ?');
  const keepEvent = db.prepare('INSERT INTO billing_events (event_id, received_at) VALUES (?, ?)');
  const forgetEvents = db.prepare('DELETE FROM billing_events WHERE received_at < ?');
  const planRow = db.prepare('SELECT occurred_at, holder_key FROM billing_plans WHERE subscription_id = ?');
  const upsertPlan = db.prepare(
    `INSERT INTO billing_plans (subscription_id, holder_key, plan, status, period_end, past_due_since, paid_through, occurred_at, updated_at)
     VALUES (@sub, @holder, @plan, @status, @periodEnd, @pastDueSince, NULL, @occurredAt, @updatedAt)
     ON CONFLICT(subscription_id) DO UPDATE SET
       plan = excluded.plan, status = excluded.status,
       period_end = COALESCE(excluded.period_end, billing_plans.period_end),
       -- A failed renewal is remembered until it is paid (active or trialing again), with the
       -- end of the period that was paid for: a cancel after it doesn't reach the moved end.
       past_due_since = CASE
         WHEN excluded.status = 'past_due' THEN COALESCE(billing_plans.past_due_since, excluded.past_due_since)
         WHEN excluded.status IN ('active', 'trialing') THEN NULL
         ELSE billing_plans.past_due_since END,
       paid_through = CASE
         WHEN excluded.status = 'past_due' AND billing_plans.past_due_since IS NULL THEN billing_plans.period_end
         WHEN excluded.status IN ('active', 'trialing') THEN NULL
         ELSE billing_plans.paid_through END,
       occurred_at = excluded.occurred_at, updated_at = excluded.updated_at`,
  );

  /**
   * A new billing id for this holder. The id itself is never stored, only its digest, so
   * the holder gets a fresh one each time they ask. Earlier ones keep working (the last
   * BILLING_IDS_KEPT): a checkout opened in one tab must still land after another tab asked
   * for a new id, or someone would pay and get nothing.
   */
  const issueId = db.transaction((holder) => {
    const id = randomBytes(32).toString('hex');
    insertId.run(digest(id), holder, now());
    pruneIds.run(holder, now() - BILLING_ID_MIN_AGE_MS, holder, BILLING_IDS_KEPT);
    return id;
  });

  /**
   * Apply one verified webhook event. Returns { status, body } for the response. Anything
   * Paddle sends that isn't about a subscription of ours is acknowledged and ignored, so
   * Paddle doesn't retry it forever.
   */
  const applyEvent = db.transaction((event) => {
    const t = now();
    forgetEvents.run(t - EVENT_KEEP_MS);
    const eventId = typeof event?.event_id === 'string' ? event.event_id : '';
    if (!PADDLE_ID.test(eventId)) return { status: 400, body: { error: 'no event id' } };
    if (seenEvent.get(eventId)) return { status: 200, body: { ok: true, repeat: true } };
    // The id is kept only once the event is settled (applied, or not ours for good). An event
    // that couldn't be applied yet answers 5xx and isn't kept, so Paddle sends it again.
    const settled = (body) => {
      keepEvent.run(eventId, t);
      return { status: 200, body: { ok: true, ...body } };
    };
    const retry = (why) => {
      console.error(`billing: NOT APPLIED, Paddle will retry: ${why}`);
      return { status: 503, body: { error: 'not applied yet; retry' } };
    };
    if (!EVENT_TYPES.has(event.event_type)) return settled({ ignored: 'event type' });
    const d = event.data ?? {};
    const sub = typeof d.id === 'string' && PADDLE_ID.test(d.id) ? d.id : '';
    const status = STATUSES.has(d.status) ? d.status : '';
    const billingId = d.custom_data?.veilcoreBillingId;
    if (!sub || !status) return settled({ ignored: 'not a subscription' });
    const occurredAt = Date.parse(event.occurred_at ?? '');
    if (!Number.isFinite(occurredAt)) return { status: 400, body: { error: 'no occurred_at' } };
    const prior = planRow.get(sub);
    let holder = prior?.holder_key;
    if (!holder) {
      if (typeof billingId !== 'string' || !BILLING_ID.test(billingId)) return settled({ ignored: 'no billing id' });
      holder = holderOfId.get(digest(billingId))?.holder_key;
      // Someone paid and nothing here says for whom: by subscription id only, so the operator
      // can match it in Paddle.
      if (!holder) return retry(`subscription ${sub} names a billing id this registry doesn't know`);
    }
    // Paddle doesn't promise order: an event older than the one already applied changes nothing.
    if (prior && occurredAt < prior.occurred_at) return settled({ ignored: 'older event' });
    const plans = new Set((d.items ?? []).map((i) => config.prices.get(i?.price?.id)).filter(Boolean));
    if (plans.size !== 1) return retry(`subscription ${sub} has no price in BILLING_PADDLE_PRICES (or more than one plan)`);
    const periodEnd = Date.parse(d.current_billing_period?.ends_at ?? '');
    upsertPlan.run({
      sub,
      holder,
      plan: [...plans][0],
      status,
      periodEnd: Number.isFinite(periodEnd) ? periodEnd : null,
      pastDueSince: status === PAST_DUE ? occurredAt : null,
      occurredAt,
      updatedAt: t,
    });
    return settled({});
  });

  const off = (res) => res.status(404).json({ error: 'paid plans are not switched on' });

  /**
   * POST /api/billing/paddle. `req.body` must be the raw bytes (express.raw, registered
   * before the server's JSON parser): the signature is over the bytes exactly as sent.
   */
  const webhook = (req, res) => {
    if (!config.enabled) return off(res);
    if (!signatureOk(req.get('paddle-signature'), req.body, config.secret, now())) {
      return res.status(401).json({ error: 'signature not valid' });
    }
    let event;
    try {
      event = JSON.parse(req.body.toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'not JSON' });
    }
    const r = applyEvent(event);
    return res.status(r.status).json(r.body);
  };

  // This hour's counts, per holder and per address: { attempts, opened }.
  const byHolder = new Map();
  const byIp = new Map();
  let checkoutHour = -1;
  const holdsARecord = db.prepare('SELECT 1 FROM records WHERE holder_key = ? LIMIT 1');
  /**
   * POST /api/billing/checkout { plan }, for the holder in `holder` (the stored key). Opens a
   * transaction in Paddle carrying a new billing id, and answers the hosted checkout link for
   * it. The billing id never leaves the registry except to Paddle.
   */
  const checkout = async (holder, body, res, ip = '') => {
    if (!config.enabled) return off(res);
    if (!holder) return res.status(401).json({ error: 'holder key required' });
    const price = config.priceOfPlan.get(body?.plan);
    if (!price) return res.status(400).json({ error: 'no such plan' });
    // A plan is for keeping records: a key that holds none has nothing to pay for yet, and
    // random keys can't open transactions in Paddle on VeilCore's account.
    if (!holdsARecord.get(holder)) return res.status(409).json({ error: 'save a record first; a plan is for the records you keep' });
    const hour = Math.floor(now() / 3_600_000);
    if (hour !== checkoutHour) {
      checkoutHour = hour;
      byHolder.clear(); // only last hour's counts: every one of them has expired
      byIp.clear();
    }
    const busy = () => res.status(429).json({ error: 'too many checkouts opened; try again in an hour' });
    const slot = (map, k) => {
      if (map.has(k)) return map.get(k);
      if (map.size >= CHECKOUT_TRACKED_PER_HOUR) return null;
      const c = { attempts: 0, opened: 0 };
      map.set(k, c);
      return c;
    };
    const h = slot(byHolder, holder);
    const a = slot(byIp, ip);
    if (!h || !a) return busy();
    if (h.opened >= CHECKOUTS_PER_HOUR || a.opened >= CHECKOUTS_PER_HOUR_PER_IP) return busy();
    if (h.attempts >= ATTEMPTS_PER_HOUR || a.attempts >= ATTEMPTS_PER_HOUR_PER_IP) return busy();
    h.attempts++;
    a.attempts++;
    const billingId = issueId(holder);
    let txn;
    try {
      const r = await fetchImpl(`${config.api}/transactions`, {
        method: 'POST',
        headers: { authorization: `Bearer ${config.apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ items: [{ price_id: price, quantity: 1 }], custom_data: { veilcoreBillingId: billingId } }),
        signal: AbortSignal.timeout(15_000),
      });
      const j = await r.json().catch(() => ({}));
      txn = r.ok && typeof j?.data?.id === 'string' && PADDLE_ID.test(j.data.id) ? j.data.id : '';
      if (!txn) console.warn(`billing: Paddle refused a checkout (HTTP ${r.status})`);
    } catch (e) {
      console.warn(`billing: Paddle unreachable for a checkout (${e?.name ?? 'error'})`);
    }
    if (!txn) return res.status(502).json({ error: 'the payment provider could not open a checkout; try again shortly' });
    h.opened++;
    a.opened++;
    return res.json({ url: `${config.checkout}?transaction_id=${encodeURIComponent(txn)}` });
  };

  /** GET /api/billing/plan, for the holder in `holder` (the stored key). */
  const planOf = (holder, recordsHeld, res) => {
    if (!config.enabled) return off(res);
    if (!holder) return res.status(401).json({ error: 'holder key required' });
    const p = currentPlan(holder);
    return res.json({
      plan: p?.plan ?? 'free',
      status: p?.status ?? null,
      periodEnd: p?.periodEnd ? new Date(p.periodEnd).toISOString() : null,
      recordsHeld,
      // What counts against the free plan: proof codes dated, records deleted or not (usedOf).
      recordsCounted: p ? recordsHeld : usedOf(holder),
      recordCap: recordCapFor(holder),
      plans: [...config.priceOfPlan.keys()],
    });
  };

  return {
    enabled: config.enabled,
    plans: config.enabled ? [...config.priceOfPlan.keys()] : [],
    recordCapFor,
    planRoom,
    wasCounted,
    noteAdded,
    uncount,
    correctionIsFree,
    noteFreeCorrection,
    webhook,
    checkout,
    planOf,
  };
};

module.exports = { createBilling, signatureOk, billingConfig, GRACE_MS, SIGNATURE_TOLERANCE_MS };
