"""Original Rust fixture specifications, using only the Rust standard library."""

from textwrap import dedent


def code(text: str) -> str:
    return dedent(text).strip() + "\n"


RUST_FAMILIES = (
    {
        "name": "rust_tenant_admin",
        "category": "authorization",
        "language": "rust",
        "split": "development",
        "source_path": "src/lib.rs",
        "assumptions": (
            "Actor is authenticated and all its fields are server-owned. is_admin grants admin "
            "rights only within actor.tenant. The requested Note comes from a trusted store, "
            "but the caller controls which note is requested. Only the owner or a tenant admin "
            "may read a note, and both must belong to the note's tenant. A Some result is sent "
            "directly to the caller without another authorization check."
        ),
        "support_files": {
            "src/types.rs": code("""
                pub struct Actor {
                    pub tenant: String,
                    pub user_id: String,
                    pub is_admin: bool,
                }

                pub struct Note {
                    pub tenant: String,
                    pub owner_id: String,
                    pub content: String,
                }
            """),
        },
        "vulnerable": code("""
            mod types;
            pub use types::{Actor, Note};

            pub fn read_note(actor: &Actor, note: &Note) -> Option<String> {
                if actor.is_admin || (actor.tenant == note.tenant && actor.user_id == note.owner_id) {
                    Some(note.content.clone())
                } else {
                    None
                }
            }
        """),
        "fixed": code("""
            mod types;
            pub use types::{Actor, Note};

            pub fn read_note(actor: &Actor, note: &Note) -> Option<String> {
                if actor.tenant == note.tenant && (actor.is_admin || actor.user_id == note.owner_id) {
                    Some(note.content.clone())
                } else {
                    None
                }
            }
        """),
        "anchors": ("if actor.is_admin ||", "Some(note.content.clone())"),
        "relevant_anchors": ("actor.tenant == note.tenant",),
    },
    {
        "name": "rust_absolute_archive_entry",
        "category": "path_traversal",
        "language": "rust",
        "split": "development",
        "source_path": "src/lib.rs",
        "assumptions": (
            "This extractor runs on a POSIX filesystem. root is an absolute server-owned "
            "directory. member is a non-NUL caller-controlled archive entry name. The caller "
            "writes entry contents to every returned path without further path checks. Empty "
            "names, absolute names, and parent traversal must be rejected; nested relative "
            "entries are valid. Assume no symlinks or filesystem races."
        ),
        "support_files": {},
        "vulnerable": code("""
            use std::path::{Component, Path, PathBuf};

            pub fn archive_destination(root: &Path, member: &str) -> Option<PathBuf> {
                let entry = Path::new(member);
                if member.is_empty()
                    || entry.components().any(|part| matches!(part, Component::ParentDir))
                {
                    return None;
                }
                Some(root.join(entry))
            }
        """),
        "fixed": code("""
            use std::path::{Component, Path, PathBuf};

            pub fn archive_destination(root: &Path, member: &str) -> Option<PathBuf> {
                let entry = Path::new(member);
                if member.is_empty()
                    || entry.components().any(|part| {
                        matches!(part, Component::ParentDir | Component::RootDir | Component::Prefix(_))
                    })
                {
                    return None;
                }
                Some(root.join(entry))
            }
        """),
        "anchors": ("matches!(part, Component::ParentDir)", "Some(root.join(entry))"),
        "relevant_anchors": ("entry.components()", "Component::RootDir"),
    },
    {
        "name": "rust_partial_batch_permissions",
        "category": "authorization",
        "language": "rust",
        "split": "heldout",
        "source_path": "src/lib.rs",
        "assumptions": (
            "request.document_ids is caller-controlled. permissions.granted is a server-owned "
            "authorization response: each flag corresponds in order to the same position in "
            "document_ids. A partial backend response can contain fewer flags than requested IDs. "
            "Delete only when every requested ID has a corresponding true flag; any count "
            "mismatch must fail closed. A Some result is passed unchanged to the deletion store. "
            "An empty request with an empty permission response is valid and deletes nothing."
        ),
        "support_files": {
            "src/types.rs": code("""
                pub struct DeletionRequest {
                    pub document_ids: Vec<String>,
                }

                pub struct PermissionResponse {
                    pub granted: Vec<bool>,
                }
            """),
        },
        "vulnerable": code("""
            mod types;
            pub use types::{DeletionRequest, PermissionResponse};

            pub fn plan_deletion(
                request: &DeletionRequest,
                permissions: &PermissionResponse,
            ) -> Option<Vec<String>> {
                if request.document_ids.iter().zip(&permissions.granted).any(|(_, allowed)| !allowed) {
                    return None;
                }
                Some(request.document_ids.clone())
            }
        """),
        "fixed": code("""
            mod types;
            pub use types::{DeletionRequest, PermissionResponse};

            pub fn plan_deletion(
                request: &DeletionRequest,
                permissions: &PermissionResponse,
            ) -> Option<Vec<String>> {
                if request.document_ids.len() != permissions.granted.len() {
                    return None;
                }
                if request.document_ids.iter().zip(&permissions.granted).any(|(_, allowed)| !allowed) {
                    return None;
                }
                Some(request.document_ids.clone())
            }
        """),
        "anchors": (".zip(&permissions.granted)", "Some(request.document_ids.clone())"),
        "relevant_anchors": ("request.document_ids.len() != permissions.granted.len()",),
    },
    {
        "name": "rust_scope_substring",
        "category": "authorization",
        "language": "rust",
        "split": "heldout",
        "source_path": "src/lib.rs",
        "assumptions": (
            "Claims came from a verified signed token; the caller cannot forge them. scopes is "
            "an ASCII whitespace-separated list of exact, case-sensitive scope names. "
            "files:write authorizes replacement of file contents; files:write:metadata grants "
            "metadata editing only and must not authorize this operation. resource_tenant is "
            "server-owned metadata for the caller-selected file. Return true only for the "
            "files:write scope in the same tenant. A true result authorizes the overwrite."
        ),
        "support_files": {
            "src/types.rs": code("""
                pub struct Claims {
                    pub tenant: String,
                    pub scopes: String,
                }
            """),
        },
        "vulnerable": code("""
            mod types;
            pub use types::Claims;

            pub fn can_overwrite(claims: &Claims, resource_tenant: &str) -> bool {
                if claims.tenant != resource_tenant {
                    return false;
                }
                claims.scopes.contains("files:write")
            }
        """),
        "fixed": code("""
            mod types;
            pub use types::Claims;

            pub fn can_overwrite(claims: &Claims, resource_tenant: &str) -> bool {
                if claims.tenant != resource_tenant {
                    return false;
                }
                claims.scopes.split_ascii_whitespace().any(|scope| scope == "files:write")
            }
        """),
        "anchors": ('claims.scopes.contains("files:write")',),
        "relevant_anchors": (
            "claims.tenant != resource_tenant",
            "claims.scopes.split_ascii_whitespace()",
        ),
    },
)
