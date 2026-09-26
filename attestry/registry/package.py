"""Turning a directory of files into something with a name you can verify.

The digest of a package is computed over the *file tree*, not over the archive
bytes. That distinction is the whole design. Tar and zip embed timestamps,
ownership and ordering, so two archives of identical content hash differently on
two machines -- and a content address that depends on who ran the build is not a
content address.

So: hash each file, sort by path, build a Merkle tree over those leaves, and take
the root. The result is reproducible anywhere, survives repacking, and gives
inclusion proofs for individual files for free. The archive that carries the
files is also written deterministically, so the bytes match too, but nothing
depends on that.

Extraction is done by hand rather than with ``TarFile.extractall``, because a
malicious archive can name a member ``../../.ssh/authorized_keys`` and older
Pythons will happily write it. Installing somebody else's skill is exactly the
situation where that matters.
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..ledger import merkle
from ..util.canonical import canonical_bytes, digest_hex
from ..util.errors import AttestryError, IntegrityError, SchemaError

__all__ = [
    "Manifest",
    "Package",
    "MANIFEST_NAME",
    "NAME_RE",
    "VERSION_RE",
    "tree_digest",
    "safe_extract",
    "DEFAULT_IGNORES",
]

MANIFEST_NAME = "skill.json"

#: Package names: lowercase, optionally scoped as ``@scope/name``.
NAME_RE = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")

#: Versions: major.minor.patch with an optional pre-release and build suffix.
VERSION_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$"
)

DEFAULT_IGNORES = (
    ".git", ".hg", ".svn", ".attestry", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".venv", "venv", "node_modules", ".DS_Store",
    "*.pyc", "*.pyo", "*.egg-info", "*.tar.gz",
)

IGNORE_FILE = ".attestryignore"

#: Refuse to pack anything enormous. A skill is code and prose; a 200 MB member
#: is either a mistake or an attempt to fill somebody's disk on install.
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024


def _matches(name: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(name, pattern)


def _ignored(relative: str, patterns: Sequence[str]) -> bool:
    parts = relative.split("/")
    for pattern in patterns:
        if any(_matches(part, pattern) for part in parts):
            return True
        if _matches(relative, pattern):
            return True
    return False


def _read_ignores(root: str) -> List[str]:
    patterns = list(DEFAULT_IGNORES)
    path = os.path.join(root, IGNORE_FILE)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    patterns.append(stripped)
    return patterns


class Manifest:
    """``skill.json``: what the package is and what it needs."""

    __slots__ = (
        "name", "version", "description", "author", "license", "entry",
        "runtime", "requires", "tools", "keywords", "homepage", "extra",
    )

    def __init__(
        self,
        name: str,
        version: str,
        description: str = "",
        author: str = "",
        license: str = "",
        entry: str = "",
        runtime: str = "",
        requires: Optional[Sequence[str]] = None,
        tools: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        homepage: str = "",
        extra: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.license = license
        self.entry = entry
        self.runtime = runtime
        self.requires = list(requires or [])
        self.tools = list(tools or [])
        self.keywords = list(keywords or [])
        self.homepage = homepage
        self.extra = dict(extra or {})

    def __repr__(self) -> str:
        return "Manifest(%s@%s)" % (self.name, self.version)

    @property
    def spec(self) -> str:
        return "%s@%s" % (self.name, self.version)

    def validate(self) -> List[str]:
        problems = []
        if not NAME_RE.match(self.name or ""):
            problems.append(
                "name %r must be lowercase, and may be scoped as @scope/name" % (self.name,)
            )
        if not VERSION_RE.match(self.version or ""):
            problems.append(
                "version %r must look like 1.2.3, optionally 1.2.3-beta.1" % (self.version,)
            )
        if not self.description:
            problems.append("no description: this is what people see before installing")
        if not self.license:
            problems.append("no license declared")
        return problems

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"name": self.name, "version": self.version}
        for field in ("description", "author", "license", "entry", "runtime", "homepage"):
            value = getattr(self, field)
            if value:
                out[field] = value
        for field in ("requires", "tools", "keywords"):
            value = getattr(self, field)
            if value:
                out[field] = value
        out.update(self.extra)
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Manifest":
        if "name" not in data or "version" not in data:
            raise SchemaError("%s needs at least a name and a version" % MANIFEST_NAME)
        known = {
            "name", "version", "description", "author", "license", "entry",
            "runtime", "requires", "tools", "keywords", "homepage",
        }
        return cls(
            name=data["name"],
            version=data["version"],
            description=data.get("description", ""),
            author=data.get("author", ""),
            license=data.get("license", ""),
            entry=data.get("entry", ""),
            runtime=data.get("runtime", ""),
            requires=data.get("requires"),
            tools=data.get("tools"),
            keywords=data.get("keywords"),
            homepage=data.get("homepage", ""),
            extra={k: v for k, v in data.items() if k not in known},
        )


def _leaf(path: str, digest: str, executable: bool) -> bytes:
    """Bytes hashed for one file. Path and mode are covered, not just content.

    Including the path stops two packages with the same files under different
    names colliding; including the executable bit stops a silent
    ``chmod +x`` from passing verification.
    """
    return merkle.leaf_hash(
        canonical_bytes({"path": path, "digest": digest, "exec": executable})
    )


def tree_digest(files: Sequence[Tuple[str, str, bool]]) -> str:
    """Merkle root over ``(path, content_digest, executable)`` triples."""
    leaves = [_leaf(path, digest, executable) for path, digest, executable in sorted(files)]
    return merkle.merkle_root(leaves).hex()


class Package:
    """A manifest plus the file contents it describes."""

    def __init__(self, manifest: Manifest, files: Mapping[str, bytes]) -> None:
        self.manifest = manifest
        # Paths are always stored POSIX-style so a package built on Windows and
        # one built on Linux produce the same digest.
        self.files: Dict[str, bytes] = {
            path.replace(os.sep, "/"): content for path, content in files.items()
        }
        self.executable: Dict[str, bool] = {}

    def __repr__(self) -> str:
        return "Package(%s, %d files, %s)" % (
            self.manifest.spec, len(self.files), self.digest()[:12]
        )

    # -- identity --------------------------------------------------------

    def file_digests(self) -> List[Tuple[str, str, bool]]:
        return sorted(
            (path, digest_hex(content), self.executable.get(path, False))
            for path, content in self.files.items()
        )

    def digest(self) -> str:
        """The content address of this package."""
        return tree_digest(self.file_digests())

    def total_bytes(self) -> int:
        return sum(len(content) for content in self.files.values())

    def inclusion_proof(self, path: str) -> Dict[str, Any]:
        """Prove one file belongs to this package without revealing the others."""
        triples = self.file_digests()
        paths = [entry[0] for entry in triples]
        if path not in paths:
            raise KeyError("%s is not in this package" % path)
        index = paths.index(path)
        leaves = [_leaf(*triple) for triple in triples]
        return {
            "package": self.manifest.spec,
            "path": path,
            "file_digest": triples[index][1],
            "index": index,
            "size": len(leaves),
            "path_proof": [node.hex() for node in merkle.audit_path(leaves, index)],
            "root": merkle.merkle_root(leaves).hex(),
        }

    @staticmethod
    def verify_inclusion(proof: Mapping[str, Any], content: Optional[bytes] = None) -> bool:
        """Check a proof from :meth:`inclusion_proof`, optionally against the file."""
        if content is not None and digest_hex(content) != proof.get("file_digest"):
            return False
        leaf = _leaf(
            proof["path"], proof["file_digest"], bool(proof.get("exec", False))
        )
        return merkle.verify_audit_path(
            leaf,
            int(proof["index"]),
            int(proof["size"]),
            [bytes.fromhex(node) for node in proof["path_proof"]],
            bytes.fromhex(proof["root"]),
        )

    # -- building --------------------------------------------------------

    @classmethod
    def from_dir(cls, directory: str) -> "Package":
        """Read a package from a directory containing ``skill.json``."""
        root = os.path.abspath(directory)
        manifest_path = os.path.join(root, MANIFEST_NAME)
        if not os.path.exists(manifest_path):
            raise AttestryError(
                "%s has no %s; a package needs a manifest" % (directory, MANIFEST_NAME)
            )
        with open(manifest_path, "r", encoding="utf-8") as handle:
            try:
                manifest = Manifest.from_dict(json.load(handle))
            except ValueError as exc:
                raise SchemaError("%s is not valid JSON: %s" % (manifest_path, exc))

        patterns = _read_ignores(root)
        files: Dict[str, bytes] = {}
        executable: Dict[str, bool] = {}
        total = 0
        for current, directories, filenames in os.walk(root):
            directories[:] = [
                d for d in sorted(directories)
                if not _ignored(os.path.relpath(os.path.join(current, d), root)
                                .replace(os.sep, "/"), patterns)
            ]
            for filename in sorted(filenames):
                absolute = os.path.join(current, filename)
                relative = os.path.relpath(absolute, root).replace(os.sep, "/")
                if relative == IGNORE_FILE or _ignored(relative, patterns):
                    continue
                if os.path.islink(absolute):
                    # Symlinks would let a package's content depend on whatever
                    # the target happens to be at install time, which defeats
                    # content addressing.
                    raise AttestryError(
                        "%s is a symlink; packages must contain real files" % relative
                    )
                size = os.path.getsize(absolute)
                if size > MAX_FILE_BYTES:
                    raise AttestryError(
                        "%s is %.1f MB, above the %d MB per-file limit"
                        % (relative, size / 1048576.0, MAX_FILE_BYTES // 1048576)
                    )
                total += size
                if total > MAX_TOTAL_BYTES:
                    raise AttestryError(
                        "package exceeds the %d MB total limit"
                        % (MAX_TOTAL_BYTES // 1048576)
                    )
                with open(absolute, "rb") as handle:
                    files[relative] = handle.read()
                executable[relative] = bool(os.stat(absolute).st_mode & 0o111)

        package = cls(manifest, files)
        package.executable = executable
        return package

    def write_dir(self, directory: str) -> str:
        """Write the package out as real files."""
        for relative, content in sorted(self.files.items()):
            target = os.path.join(directory, *relative.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(content)
            if self.executable.get(relative):
                os.chmod(target, 0o755)
        return directory

    # -- archives --------------------------------------------------------

    def to_archive_bytes(self) -> bytes:
        """A deterministic ``.tar.gz``: same content in, same bytes out.

        Timestamps, ownership and member order are all pinned, and gzip's own
        mtime field is zeroed. Reproducible archives are not strictly required --
        verification uses the tree digest -- but they make a published artefact
        checkable by anyone who repacks the source.
        """
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for relative, content in sorted(self.files.items()):
                info = tarfile.TarInfo(name=relative)
                info.size = len(content)
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if self.executable.get(relative) else 0o644
                archive.addfile(info, io.BytesIO(content))
        import gzip

        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as gz:
            gz.write(raw.getvalue())
        return compressed.getvalue()

    def write_archive(self, path: str) -> str:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(self.to_archive_bytes())
        return path

    @classmethod
    def from_archive_bytes(cls, data: bytes) -> "Package":
        files: Dict[str, bytes] = {}
        executable: Dict[str, bool] = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                if not member.isfile():
                    raise IntegrityError(
                        "archive member %r is not a regular file" % member.name
                    )
                safe = _safe_member_name(member.name)
                if member.size > MAX_FILE_BYTES:
                    raise IntegrityError("archive member %r is too large" % member.name)
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                files[safe] = handle.read()
                executable[safe] = bool(member.mode & 0o111)
        if MANIFEST_NAME not in files:
            raise IntegrityError("archive contains no %s" % MANIFEST_NAME)
        manifest = Manifest.from_dict(json.loads(files[MANIFEST_NAME].decode("utf-8")))
        package = cls(manifest, files)
        package.executable = executable
        return package

    @classmethod
    def from_archive(cls, path: str) -> "Package":
        with open(path, "rb") as handle:
            return cls.from_archive_bytes(handle.read())


def _safe_member_name(name: str) -> str:
    """Reject archive member names that would escape the extraction directory."""
    normalised = name.replace("\\", "/").lstrip("/")
    if normalised.startswith("../") or "/../" in normalised or normalised == "..":
        raise IntegrityError(
            "archive member %r tries to escape the extraction directory" % name
        )
    if re.match(r"^[A-Za-z]:", normalised):
        raise IntegrityError("archive member %r has an absolute Windows path" % name)
    return normalised


def safe_extract(archive_bytes: bytes, destination: str) -> str:
    """Extract an archive without letting it write outside ``destination``."""
    package = Package.from_archive_bytes(archive_bytes)
    os.makedirs(destination, exist_ok=True)
    return package.write_dir(destination)
