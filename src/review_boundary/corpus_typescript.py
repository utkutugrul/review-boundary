"""Original TypeScript fixture specifications, with no external package dependencies."""

from textwrap import dedent


def code(text: str) -> str:
    return dedent(text).strip() + "\n"


TYPESCRIPT_FAMILIES = (
    {
        "name": "ts_batch_export",
        "category": "authorization",
        "language": "typescript",
        "split": "development",
        "source_path": "src/export.ts",
        "assumptions": (
            "actorTenant is the authenticated caller's server-owned tenant ID. requestedIds is "
            "caller-controlled. records is a trusted complete document store keyed by unique ID. "
            "Export a nonempty batch only if every requested document belongs to actorTenant. "
            "Return null for missing documents, empty requests, or unauthorized documents. "
            "The returned values are sent directly to the caller without further access checks."
        ),
        "support_files": {
            "package.json": '{"private":true,"type":"module"}\n',
            "src/types.ts": code("""
                export interface StoredDocument {
                  tenantId: string;
                  value: string;
                }
            """),
        },
        "vulnerable": code("""
            import type { StoredDocument } from "./types.ts";

            export function selectExport(
              records: ReadonlyMap<string, StoredDocument>,
              actorTenant: string,
              requestedIds: readonly string[],
            ): string[] | null {
              if (requestedIds.length === 0) return null;
              const rows = requestedIds.map((id) => records.get(id));
              if (rows.some((row) => row === undefined)) return null;
              const documents = rows as StoredDocument[];
              if (!documents.some((document) => document.tenantId === actorTenant)) return null;
              return documents.map((document) => document.value);
            }
        """),
        "fixed": code("""
            import type { StoredDocument } from "./types.ts";

            export function selectExport(
              records: ReadonlyMap<string, StoredDocument>,
              actorTenant: string,
              requestedIds: readonly string[],
            ): string[] | null {
              if (requestedIds.length === 0) return null;
              const rows = requestedIds.map((id) => records.get(id));
              if (rows.some((row) => row === undefined)) return null;
              const documents = rows as StoredDocument[];
              if (!documents.every((document) => document.tenantId === actorTenant)) return null;
              return documents.map((document) => document.value);
            }
        """),
        "anchors": ("documents.some", "return documents.map"),
        "relevant_anchors": ("requestedIds.map", "documents.every"),
    },
    {
        "name": "ts_hmac_prefix",
        "category": "signature_verification",
        "language": "typescript",
        "split": "development",
        "source_path": "src/webhook.ts",
        "assumptions": (
            "body is the exact raw webhook body and signature is an untrusted string. "
            "secret is a nonempty server-owned key. Returning true authorizes event processing. "
            "The protocol requires a complete 64-character hexadecimal HMAC-SHA256 signature, "
            "accepting either letter case. Missing, truncated, or incorrect signatures must fail. "
            "Replay handling and key rotation are outside this helper's scope."
        ),
        "support_files": {"package.json": '{"private":true,"type":"module"}\n'},
        "vulnerable": code("""
            import { createHmac } from "node:crypto";

            export function verifyWebhook(body: string, signature: string, secret: string): boolean {
              const expected = createHmac("sha256", secret).update(body).digest("hex");
              return expected.startsWith(signature.toLowerCase());
            }
        """),
        "fixed": code("""
            import { createHmac, timingSafeEqual } from "node:crypto";

            export function verifyWebhook(body: string, signature: string, secret: string): boolean {
              if (signature.length !== 64 || !/^[0-9a-f]{64}$/i.test(signature)) return false;
              const expected = createHmac("sha256", secret).update(body).digest();
              const supplied = Buffer.from(signature, "hex");
              return timingSafeEqual(expected, supplied);
            }
        """),
        "anchors": ("return expected.startsWith",),
        "relevant_anchors": (
            "const expected =",
            "test(signature)",
            "const supplied =",
            "return timingSafeEqual",
        ),
    },
    {
        "name": "ts_decode_after_check",
        "category": "path_traversal",
        "language": "typescript",
        "split": "heldout",
        "source_path": "src/download.ts",
        "assumptions": (
            "This service runs on a POSIX filesystem. root is an absolute server-owned download "
            "directory. encodedName is caller-controlled and uses URL percent encoding; the "
            "decoded name never contains a NUL byte. The caller opens any returned path directly. "
            "Only paths inside root are authorized. Reject malformed percent encoding. Assume "
            "a stable filesystem with no symlinks or filesystem races."
        ),
        "support_files": {"package.json": '{"private":true,"type":"module"}\n'},
        "vulnerable": code("""
            import { posix as path } from "node:path";

            export function downloadPath(root: string, encodedName: string): string | null {
              const base = path.resolve(root);
              let decoded: string;
              try {
                decoded = decodeURIComponent(encodedName);
              } catch {
                return null;
              }
              const checked = path.resolve(base, encodedName);
              const relative = path.relative(base, checked);
              if (relative === ".." || relative.startsWith("../") || path.isAbsolute(relative)) {
                return null;
              }
              return path.resolve(base, decoded);
            }
        """),
        "fixed": code("""
            import { posix as path } from "node:path";

            export function downloadPath(root: string, encodedName: string): string | null {
              const base = path.resolve(root);
              let decoded: string;
              try {
                decoded = decodeURIComponent(encodedName);
              } catch {
                return null;
              }
              const checked = path.resolve(base, decoded);
              const relative = path.relative(base, checked);
              if (relative === ".." || relative.startsWith("../") || path.isAbsolute(relative)) {
                return null;
              }
              return checked;
            }
        """),
        "anchors": ("path.resolve(base, encodedName)", "return path.resolve(base, decoded)"),
        "relevant_anchors": (
            "decodeURIComponent(encodedName)",
            "const relative =",
            "relative.startsWith",
            "const checked =",
            "return checked",
        ),
    },
    {
        "name": "ts_membership_cache",
        "category": "authorization",
        "language": "typescript",
        "split": "heldout",
        "source_path": "src/membership.ts",
        "assumptions": (
            "userId identifies an authenticated user and is server-owned. workspaceId is "
            "caller-controlled. fetchRole is a trusted lookup of that user's role in exactly "
            "that workspace. Roles remain stable during the cache lifetime. A MembershipGate "
            "instance is reused across requests and workspaces. Only an admin in the requested "
            "workspace may administer it; being an admin elsewhere grants no rights."
        ),
        "support_files": {
            "package.json": '{"private":true,"type":"module"}\n',
            "src/types.ts": code("""
                export type Role = "admin" | "member" | null;
                export type RoleLookup = (userId: string, workspaceId: string) => Role;
            """),
        },
        "vulnerable": code("""
            import type { Role, RoleLookup } from "./types.ts";

            export class MembershipGate {
              private cached = new Map<string, Role>();
              private fetchRole: RoleLookup;

              constructor(fetchRole: RoleLookup) {
                this.fetchRole = fetchRole;
              }

              canAdminister(userId: string, workspaceId: string): boolean {
                const key = userId;
                if (!this.cached.has(key)) {
                  this.cached.set(key, this.fetchRole(userId, workspaceId));
                }
                return this.cached.get(key) === "admin";
              }
            }
        """),
        "fixed": code("""
            import type { Role, RoleLookup } from "./types.ts";

            export class MembershipGate {
              private cached = new Map<string, Role>();
              private fetchRole: RoleLookup;

              constructor(fetchRole: RoleLookup) {
                this.fetchRole = fetchRole;
              }

              canAdminister(userId: string, workspaceId: string): boolean {
                const key = JSON.stringify([userId, workspaceId]);
                if (!this.cached.has(key)) {
                  this.cached.set(key, this.fetchRole(userId, workspaceId));
                }
                return this.cached.get(key) === "admin";
              }
            }
        """),
        "anchors": ("const key = userId", "return this.cached.get"),
        "relevant_anchors": ("const key =", "this.cached.has(key)", "this.cached.set(key"),
    },
)
