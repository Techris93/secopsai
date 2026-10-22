// R2-backed research-ledger checkpoints shared by the Container runner and
// the free GitHub Actions runner (via the secopsai-ledger-store Worker).
const SNAPSHOT_PREFIX = "ledger/snapshots/";
const LATEST_POINTER = "ledger/LATEST";
const KEEP_SNAPSHOTS = 4;
const MAX_PART_BYTES = 64 * 1024 * 1024;

export function json(payload, status = 200) {
  return Response.json(payload, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    },
  });
}

export function timingSafeEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < a.byteLength; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

export function bearer(request) {
  const header = request.headers.get("authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

const MANIFEST_PREFIX = "ledger/manifests/";
const CHUNK_POINTER = "ledger/LATEST_CHUNKED";
const HASH = /^[a-f0-9]{64}$/;

export function validCheckpointManifest(m) {
  if (m?.version === 4) {
    return m.base?.version === 3 && validCheckpointManifest(m.base) && m.block_bytes === 4096
      && HASH.test(m.sha256 || "") && Number.isSafeInteger(m.size_bytes) && m.size_bytes > 0 && m.size_bytes <= 900 * 28 * 1024 * 1024
      && Number.isFinite(Date.parse(m.captured_at)) && Date.parse(m.base.captured_at) <= Date.parse(m.captured_at)
      && Array.isArray(m.patches) && m.base.chunks.length + m.patches.length <= 900
      && m.patches.every(c => HASH.test(c.sha256 || "") && HASH.test(c.raw_sha256 || "")
        && Number.isSafeInteger(c.size_bytes) && c.size_bytes > 0 && c.size_bytes <= 32 * 1024 * 1024
        && Number.isSafeInteger(c.raw_size_bytes) && c.raw_size_bytes >= 8 && c.raw_size_bytes <= 28 * 1024 * 1024);
  }
  if (!m || m.version !== 3 || !HASH.test(m.sha256 || "") || !Array.isArray(m.chunks) || !m.chunks.length || m.chunks.length > 900
      || !Number.isSafeInteger(m.size_bytes) || m.size_bytes <= 0 || !Number.isFinite(Date.parse(m.captured_at))) return false;
  let total = 0;
  for (const c of m.chunks) {
    if (!HASH.test(c.sha256 || "") || !HASH.test(c.raw_sha256 || "") || !Number.isSafeInteger(c.size_bytes) || c.size_bytes <= 0 || c.size_bytes > 32 * 1024 * 1024
        || !Number.isSafeInteger(c.raw_size_bytes) || c.raw_size_bytes <= 0 || c.raw_size_bytes > 28 * 1024 * 1024) return false;
    total += c.raw_size_bytes;
  }
  return total === m.size_bytes;
}

export async function handleChunkedCheckpoint(request, bucket) {
  const original = new URL(request.url).pathname;
  const drill = original.startsWith("/recovery-drill/");
  const path = drill ? original.slice("/recovery-drill".length) : original;
  const pointerKey = drill ? "ledger/recovery-drills/LATEST" : CHUNK_POINTER;
  const prefix = drill ? "ledger/recovery-drills/manifests/" : MANIFEST_PREFIX;
  if (path === "/checkpoint-manifest" && request.method === "GET") {
    const pointer = await bucket.get(pointerKey);
    if (!pointer) return json({error: "no_chunked_checkpoint"}, 404);
    const object = await bucket.get(await pointer.text());
    if (!object) return json({error: "checkpoint_manifest_missing"}, 503);
    return new Response(object.body, {headers: {"content-type": "application/json", "cache-control": "no-store"}});
  }
  if (path !== "/checkpoints" || request.method !== "POST") return null;
  const length = Number(request.headers.get("content-length"));
  if (!Number.isSafeInteger(length) || length <= 0 || length > 512 * 1024) return json({error: "manifest_size_invalid"}, 413);
  const encoded = await request.text();
  if (new TextEncoder().encode(encoded).byteLength > 512 * 1024) return json({error: "manifest_size_invalid"}, 413);
  let m;
  try {m = JSON.parse(encoded);} catch {return json({error: "invalid_checkpoint_manifest"},400);}
  if (!validCheckpointManifest(m) || Date.parse(m.captured_at) > Date.now() + 300000) return json({error: "invalid_checkpoint_manifest"}, 400);
  // Stay below the free plan's internal-service request budget and six open connections.
  const chunks = m.version === 4 ? [...m.base.chunks, ...m.patches] : m.chunks;
  for (let i = 0; i < chunks.length; i += 6) {
    const group = chunks.slice(i, i + 6);
    const objects = await Promise.all(group.map(c => bucket.head(`artifacts/sha256/${c.sha256}`)));
    if (objects.some((o, j) => !o || o.size !== group[j].size_bytes || o.customMetadata?.sha256 !== group[j].sha256))
      return json({error: "checkpoint_chunk_missing_or_corrupt"}, 409);
  }
  const body = JSON.stringify(m);
  const manifestHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))), b => b.toString(16).padStart(2,"0")).join("");
  const key = `${prefix}${m.captured_at.replace(/[:.]/g, "-")}-${manifestHash}.json`;
  await bucket.put(key, body, {httpMetadata: {contentType: "application/json"}, customMetadata: {captured_at: m.captured_at, size_bytes: String(m.size_bytes), protocol: `ledger-checkpoint-v${m.version}`}});
  const current = await bucket.get(pointerKey);
  if (current && await current.text() > key) return json({key, superseded: true});
  await bucket.put(pointerKey, key);
  return json({key, protocol: `ledger-checkpoint-v${m.version}`, completion_retry_safe: true});
}

export async function handleLedgerRequest(request, bucket) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);
  const chunked = await handleChunkedCheckpoint(request, bucket);
  if (chunked) return chunked;
  // Private immutable chunks and manifests. R2 checks the supplied SHA-256
  // against the streamed bytes; existing objects are never overwritten.
  const artifact = url.pathname.match(/^\/artifact-objects\/([a-f0-9]{64})$/);
  if (artifact) {
    const hash = artifact[1];
    const objectKey = `artifacts/sha256/${hash}`;
    if (request.method === "PUT") {
      const length = Number(request.headers.get("content-length"));
      if (!Number.isSafeInteger(length) || length <= 0) return json({error: "content_length_required"}, 411);
      if (length > 32 * 1024 * 1024) return json({error: "object_too_large"}, 413);
      // Read the bounded body first so the three outcomes stay distinct: a
      // complete body with the wrong content address is a permanent 400; a
      // transfer cut short or a storage error is a retryable 503; an identical
      // object already stored (a concurrent or retried upload) is success.
      let bytes;
      try {
        bytes = new Uint8Array(await request.arrayBuffer());
      } catch {
        return json({error: "object_transfer_incomplete"}, 503);
      }
      if (bytes.byteLength !== length) return json({error: "object_transfer_incomplete"}, 503);
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
      if (digest !== hash) {
        // Unchanged contract: a different body for a stored address is a
        // conflict (409); otherwise the body is simply invalid (400).
        const stored = await bucket.head(objectKey).catch(() => null);
        return stored ? json({error: "object_integrity_failure"}, 409) : json({error: "object_write_or_integrity_failure"}, 400);
      }
      try {
        await bucket.put(objectKey, bytes, {sha256: hash,
          onlyIf: new Headers({"If-None-Match": "*"}),
          httpMetadata: {contentType: "application/octet-stream"}, customMetadata: {sha256: hash}});
      } catch {
        const existing = await bucket.head(objectKey).catch(() => null);
        if (existing && existing.size === length && existing.customMetadata?.sha256 === hash) {
          return json({sha256: hash, size_bytes: existing.size});
        }
        return json({error: "object_write_unavailable"}, 503);
      }
      const object = await bucket.head(objectKey);
      if (!object || object.size !== length || object.customMetadata?.sha256 !== hash) return json({error: "object_integrity_failure"}, 409);
      return json({sha256: hash, size_bytes: object.size});
    }
    if (request.method === "HEAD" || request.method === "GET") {
      const object = request.method === "HEAD" ? await bucket.head(objectKey) : await bucket.get(objectKey);
      if (!object) return json({error: "object_missing"}, 404);
      return new Response(request.method === "HEAD" ? null : object.body, {headers: {
        "content-type": "application/octet-stream", "content-length": String(object.size),
        "x-artifact-sha256": hash, "cache-control": "no-store", "x-content-type-options": "nosniff",
        "content-disposition": "attachment", "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      }});
    }
    return json({error: "method_not_allowed"}, 405);
  }
  if (request.method === "GET" && url.pathname === "/status") {
    const chunkedPointer = await bucket.get(CHUNK_POINTER);
    if (chunkedPointer) {
      const key = await chunkedPointer.text(), object = await bucket.head(key);
      return json({protocol: object?.customMetadata?.protocol || "ledger-checkpoint-v3", completion_retry_safe: true, latest_key: key,
        size_bytes: Number(object?.customMetadata?.size_bytes) || null, captured_at: object?.customMetadata?.captured_at || null,
        uploaded_at: object?.uploaded ? new Date(object.uploaded).toISOString() : null, checkpoint_available: Boolean(object)});
    }
    const pointer = await bucket.get(LATEST_POINTER);
    const key = pointer ? await pointer.text() : null;
    const object = key ? await bucket.head(key) : null;
    return json({ protocol: "ledger-checkpoint-v2", completion_retry_safe: true,
      latest_key: object ? key : null, size_bytes: object?.size ?? null,
      uploaded_at: object?.uploaded ? new Date(object.uploaded).toISOString() : null,
      checkpoint_available: Boolean(object) });
  }

  if (request.method === "GET" && url.pathname === "/snapshot") {
    if (await bucket.get(CHUNK_POINTER)) return json({error: "incremental_checkpoint_requires_v3_client"},409);
    const pointer = await bucket.get(LATEST_POINTER);
    if (!pointer) return json({ error: "no_snapshot" }, 404);
    const object = await bucket.get(await pointer.text());
    if (!object) return json({ error: "snapshot_missing" }, 404);
    return new Response(object.body, { headers: { "content-type": "application/gzip" } });
  }

  if (request.method === "POST" && url.pathname === "/uploads") {
    const key = `${SNAPSHOT_PREFIX}${new Date().toISOString().replace(/[:.]/g, "-")}.db.gz`;
    const upload = await bucket.createMultipartUpload(key, { httpMetadata: { contentType: "application/gzip" } });
    return json({ upload_id: upload.uploadId, key, completion_retry_safe: true });
  }

  const key = url.searchParams.get("key") || "";
  if (parts[0] === "uploads" && parts[1] && key.startsWith(SNAPSHOT_PREFIX) && !key.includes("..")) {
    const upload = bucket.resumeMultipartUpload(key, parts[1]);
    if (request.method === "PUT" && parts[2] === "parts" && /^\d{1,5}$/.test(parts[3] || "")) {
      const length = Number(request.headers.get("content-length") || 0);
      if (length > MAX_PART_BYTES) return json({ error: "part_too_large" }, 413);
      if (!length) return json({ error: "content_length_required" }, 411);
      // A body with Content-Length is a fixed-length stream, which R2 accepts
      // without buffering the 32 MiB part in Worker memory.
      const uploaded = await upload.uploadPart(Number(parts[3]), request.body);
      return json({ etag: uploaded.etag });
    }
    if (request.method === "POST" && parts[2] === "complete") {
      const body = await request.json().catch(() => null);
      if (!Array.isArray(body?.parts) || !body.parts.length) return json({ error: "parts_required" }, 400);
      // A response can be lost after R2 completed the object. R2 no longer
      // has that multipart upload, so use the completed object on a retry.
      if (!(await bucket.head(key))) {
        try {
          await upload.complete(body.parts);
        } catch (error) {
          // Concurrent attempts may both have observed no object initially.
          if (!(await bucket.head(key))) throw error;
        }
      }
      // Advance the pointer only after the snapshot object is complete.
      // A delayed retry of an older completed upload must not roll back LATEST.
      // The workflow concurrency group still enforces a single ledger writer.
      const pointer = await bucket.get(LATEST_POINTER);
      if (pointer && await pointer.text() > key) return json({ key, superseded: true });
      await bucket.put(LATEST_POINTER, key);
      await pruneSnapshots(bucket, key);
      return json({ key });
    }
  }
  return json({ error: "not_found" }, 404);
}

async function pruneSnapshots(bucket, latestKey) {
  const listing = await bucket.list({ prefix: SNAPSHOT_PREFIX });
  const keys = (listing.objects || []).map((object) => object.key).sort();
  const stale = keys.filter((key) => key !== latestKey).slice(0, Math.max(0, keys.length - KEEP_SNAPSHOTS));
  if (stale.length) await bucket.delete(stale);
}

