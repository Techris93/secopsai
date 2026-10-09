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

export async function handleLedgerRequest(request, bucket) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);

  if (request.method === "GET" && url.pathname === "/snapshot") {
    const pointer = await bucket.get(LATEST_POINTER);
    if (!pointer) return json({ error: "no_snapshot" }, 404);
    const object = await bucket.get(await pointer.text());
    if (!object) return json({ error: "snapshot_missing" }, 404);
    return new Response(object.body, { headers: { "content-type": "application/gzip" } });
  }

  if (request.method === "POST" && url.pathname === "/uploads") {
    const key = `${SNAPSHOT_PREFIX}${new Date().toISOString().replace(/[:.]/g, "-")}.db.gz`;
    const upload = await bucket.createMultipartUpload(key, { httpMetadata: { contentType: "application/gzip" } });
    return json({ upload_id: upload.uploadId, key });
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
      await upload.complete(body.parts);
      // Advance the pointer only after the snapshot object is complete.
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

