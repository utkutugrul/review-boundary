# Upstream case candidates

Source verification: November 6, 2026. **One upstream source issue is now
implemented and reproduced:** the [pinned PyJWT corpus](upstream-pyjwt.md), with
four conditions and independent behavior controls. The other five entries
remain source-researched candidates. No paid model evaluation was performed.

The official advisories, selected commit objects, parent arrays, and pinned
license files were inspected. Commit links below contain full immutable SHAs.
A parent is a candidate comparison revision, not a demonstrated vulnerable
baseline. Except for the documented PyJWT reproduction, behavior checks below
remain **unverified here**, including tests already present upstream.

| Priority / candidate | Advisory and verified history | Narrow scope and behavior check to validate | Pinned license |
| --- | --- | --- | --- |
| 1. PyJWT, Python | [GHSA-ffqj-6fqr-9h24](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24); [fix 9c528670](https://github.com/jpadilla/pyjwt/commit/9c528670c455b8d948aff95ed50e22940d1ad3fc), [parent 24b29adf](https://github.com/jpadilla/pyjwt/commit/24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc). | Reject recognized asymmetric key formats used as HMAC secrets; retain genuine EdDSA/ES256 verification. | [MIT](https://github.com/jpadilla/pyjwt/blob/24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc/LICENSE) |
| 2. Next.js, TypeScript | [GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw); [fix 52a078da](https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2), [parent 4698ad64](https://github.com/vercel/next.js/commit/4698ad6478cc85a7283a8c41edfbba023dadf57d). | Filter untrusted middleware subrequest headers; preserve middleware redirects and genuine internal requests. | [MIT](https://github.com/vercel/next.js/blob/4698ad6478cc85a7283a8c41edfbba023dadf57d/license.md) |
| 3. zip2, Rust | [GHSA-94vh-gphv-8pm8](https://github.com/zip-rs/zip2/security/advisories/GHSA-94vh-gphv-8pm8); [fix a2e062f3](https://github.com/zip-rs/zip2/commit/a2e062f37066c3b12860a32eb1cb44856cfb7afe), parents [c6ba2012](https://github.com/zip-rs/zip2/commit/c6ba2012352c1b7ba6340d38207538c71aacc797) and [0199ac2c](https://github.com/zip-rs/zip2/commit/0199ac2cb8e9a5d7e645e53d51838655d8e15148). | Earlier symlinks must not redirect later extraction outside the destination; preserve ordinary extraction. | [MIT, with test-data exceptions](https://github.com/zip-rs/zip2/blob/c6ba2012352c1b7ba6340d38207538c71aacc797/LICENSE) |
| 4. node-jws, JavaScript | [GHSA-869p-cjfg-cm3x](https://github.com/auth0/node-jws/security/advisories/GHSA-869p-cjfg-cm3x); [fix 34c45b2c](https://github.com/auth0/node-jws/commit/34c45b2c04434f925b638de6a061de9339c0ea2e), parents [b9fb8d30](https://github.com/auth0/node-jws/commit/b9fb8d30e9c009ade6379f308590f1b0703eefc3) and [49bc39b1](https://github.com/auth0/node-jws/commit/49bc39b1f5509a630e0c6849527d8bc66b29ddf5). | Streamed HMAC verification under the advisory's secret-lookup preconditions. Check absent-secret rejection and explicit empty-secret compatibility. | [MIT](https://github.com/auth0/node-jws/blob/b9fb8d30e9c009ade6379f308590f1b0703eefc3/LICENSE) |
| 5. node-forge, JavaScript | [GHSA-cfm4-qjh2-4765](https://github.com/digitalbazaar/forge/security/advisories/GHSA-cfm4-qjh2-4765); [fix 3f0b49a0](https://github.com/digitalbazaar/forge/commit/3f0b49a0573ef1bb7af7f5673c0cfebf00424df1), [parent c20f3093](https://github.com/digitalbazaar/forge/commit/c20f309311d83445e11abe7c313cc4b467c18914). | Reject malformed RSA DigestInfo structures while preserving valid signatures. Isolate this issue from a patch covering three verification defects. | [BSD-3-Clause or GPL-2.0](https://github.com/digitalbazaar/forge/blob/c20f309311d83445e11abe7c313cc4b467c18914/LICENSE) |
| 6. pyLoad, Python | [GHSA-7gvf-3w72-p2pg](https://github.com/pyload/pyload/security/advisories/GHSA-7gvf-3w72-p2pg); [fix 33c55da0](https://github.com/pyload/pyload/commit/33c55da084320430edfd941b60e3da0eb1be9443), [parent 4aa578c8](https://github.com/pyload/pyload/commit/4aa578c8d4be7f2a047574ac3d722940a0345f40). | Download-path redirect checks using the connected IP. An isolated redirect test and libcurl callback behavior still need validation. | [AGPL-3.0-or-later declaration](https://github.com/pyload/pyload/blob/4aa578c8d4be7f2a047574ac3d722940a0345f40/README.md#open-source-license), [license text](https://github.com/pyload/pyload/blob/4aa578c8d4be7f2a047574ac3d722940a0345f40/LICENSE.md) |

PyJWT is the smallest starting point. Its fix adds advisory tests rejecting
HS256 tokens using SSH public keys while accepting genuine asymmetric tokens.
The relevant review path spans `api_jws.py`, `algorithms.py`, and `utils.py`.
The change expands key-format detection; it does not establish that every form
of algorithm confusion is prevented. [Upstream patch](https://github.com/jpadilla/pyjwt/commit/9c528670c455b8d948aff95ed50e22940d1ad3fc).

Next.js is the stronger cross-file candidate: initialization creates an internal
identifier, the header filter checks it, and sandbox subrequests attach it.
The added end-to-end test expects the middleware redirect to remain a 307 after
a forged subrequest header. A reduced function-only test has not been shown
equivalent to the full runtime. [Upstream patch](https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2).

For zip2, the merge's first-parent diff **does add containment regression tests**
in both `src/read.rs` and `src/read/stream.rs`; it is incorrect to describe this
patch as having no tests. Their execution and platform compatibility remain
unverified. [Commit and tests](https://github.com/zip-rs/zip2/commit/a2e062f37066c3b12860a32eb1cb44856cfb7afe).

Two lower-priority details matter: Forge's additional
[bb822c02 commit](https://github.com/digitalbazaar/forge/commit/bb822c02df0b61211836472e29b9790cc541cdb2)
only adds changelog advisory links. pyLoad's historical download-path fix did
not cover the separate `parse_urls` path, according to its
[follow-on advisory](https://github.com/pyload/pyload/security/advisories/GHSA-8rp3-xc6w-5qp5).
Repository licenses do not settle every copied test, dependency, or data file;
preserve notices and record per-file exceptions before redistribution.

The next intake steps are:

1. Prepare an evaluator-only manifest for **Next.js** with both pinned
   revisions, file hashes, dependency locks, license inventories, and the minimal
   call graph. Keep advisories, reference patches, and oracle tests outside the
   reviewer-visible snapshot. Treat aliases and backports as one source issue.
2. Extend the PyJWT pilot's human rubric validation and build Next.js behavior
   checks in its full runtime. Require the pre-fix revision to fail the target check, the
   fix to pass it, and ordinary behavior to pass on both. Only then validate a
   reduced slice. Queue zip2 next, explicitly selecting a merge parent and checking
   normal files alongside both containment tests.

Admission remains governed by the [realistic corpus plan](realistic-corpus-plan.md).
The PyJWT pilot is admitted; the remaining entries are candidates. This is not
a six-issue benchmark or evidence of model performance.
