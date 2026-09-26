"""The registry itself: publish, resolve, install -- with the ledger as the index.

There is no server. The list of what exists is the set of ``registry.publish``
entries in a ledger, each signed by whoever published it and chained to
everything published before. That single substitution buys the properties a
centralised registry provides socially rather than cryptographically:

* **provenance** -- a publication is signed, so "who published this" is a fact
  about the entry rather than a claim about an account;
* **immutability** -- republishing a version with different content is refused,
  because the earlier entry is still in the chain saying what that version was;
* **transparency** -- you cannot show one person one version and another person
  a different one without producing two ledgers that visibly fork;
* **no operator** -- sync a ledger over git, a URL, a shared drive or a USB
  stick; nothing needs to be paid for or kept running.

What it does not buy is namespace arbitration. Two people can publish the name
``pdf-tools`` from different keys, and no amount of hashing decides which one
deserves it. :meth:`Registry.conflicts` surfaces that, and trust settles it: you
install from keys you chose, which is the honest answer and roughly how you
already decide whose code to run.
"""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..ledger.chain import Ledger
from ..ledger.keys import KeyPair
from ..ledger.trust import TrustStore
from ..util.errors import AttestryError, ForkDetected, IntegrityError, TrustError
from ..util.timeutil import now_rfc3339
from .package import VERSION_RE, Manifest, Package

__all__ = ["Registry", "Publication", "Conflict", "parse_spec", "version_key", "fetch_source"]

_SPEC = re.compile(r"^(?P<name>(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)"
                   r"(?:@(?P<range>.+))?$")

#: How large a fetched archive may be before we stop reading it.
MAX_FETCH_BYTES = 128 * 1024 * 1024


def version_key(version: str) -> tuple:
    """Sort key implementing the parts of semver ordering that matter here.

    A pre-release sorts below the release it precedes, so ``2.0.0-rc.1`` never
    wins over ``1.9.9`` by accident, and ``latest`` never silently resolves to
    a release candidate.
    """
    match = VERSION_RE.match(version or "")
    if not match:
        return (0, 0, 0, 1, ())
    major, minor, patch, pre = (
        int(match.group(1)), int(match.group(2)), int(match.group(3)), match.group(4)
    )
    if not pre:
        return (major, minor, patch, 1, ())
    identifiers: List[tuple] = []
    for piece in pre.split("."):
        if piece.isdigit():
            identifiers.append((0, int(piece), ""))
        else:
            identifiers.append((1, 0, piece))
    return (major, minor, patch, 0, tuple(identifiers))


def parse_spec(spec: str) -> Tuple[str, str]:
    """``pdf-tools@^1.2.0`` becomes ``("pdf-tools", "^1.2.0")``."""
    match = _SPEC.match(spec.strip())
    if not match:
        raise AttestryError(
            "%r is not a package spec; expected name, name@1.2.3, name@latest, "
            "name@^1.2.0 or name@>=1.2.0" % (spec,)
        )
    return match.group("name"), (match.group("range") or "latest")


def _satisfies(version: str, wanted: str) -> bool:
    if wanted in ("latest", "*", ""):
        return True
    if wanted.startswith("^"):
        base = wanted[1:]
        left, right = version_key(version), version_key(base)
        return left[0] == right[0] and left >= right
    if wanted.startswith("~"):
        base = wanted[1:]
        left, right = version_key(version), version_key(base)
        return left[:2] == right[:2] and left >= right
    if wanted.startswith(">="):
        return version_key(version) >= version_key(wanted[2:])
    if wanted.startswith(">"):
        return version_key(version) > version_key(wanted[1:])
    if wanted.startswith("<="):
        return version_key(version) <= version_key(wanted[2:])
    if wanted.startswith("<"):
        return version_key(version) < version_key(wanted[1:])
    return version == wanted


class Publication:
    """One published version, as recorded in the ledger."""

    __slots__ = (
        "name", "version", "digest", "manifest", "publisher", "seq", "ts",
        "sources", "files", "revoked", "revoke_reason", "trusted", "trust_note",
    )

    def __init__(
        self,
        name: str,
        version: str,
        digest: str,
        manifest: Manifest,
        publisher: str = "",
        seq: int = -1,
        ts: str = "",
        sources: Optional[Sequence[str]] = None,
        files: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> None:
        self.name = name
        self.version = version
        self.digest = digest
        self.manifest = manifest
        self.publisher = publisher
        self.seq = seq
        self.ts = ts
        self.sources = list(sources or [])
        self.files = list(files or [])
        self.revoked = False
        self.revoke_reason = ""
        self.trusted = True
        self.trust_note = ""

    def __repr__(self) -> str:
        return "Publication(%s@%s, %s%s)" % (
            self.name, self.version, self.digest[:12],
            ", revoked" if self.revoked else "",
        )

    @property
    def spec(self) -> str:
        return "%s@%s" % (self.name, self.version)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "publisher": self.publisher,
            "seq": self.seq,
            "ts": self.ts,
            "sources": self.sources,
            "revoked": self.revoked,
            "revoke_reason": self.revoke_reason,
            "trusted": self.trusted,
            "description": self.manifest.description,
        }

    def describe(self) -> str:
        flags = []
        if self.revoked:
            flags.append("REVOKED: %s" % self.revoke_reason)
        if not self.trusted:
            flags.append("UNTRUSTED: %s" % self.trust_note)
        return "%-28s %-10s %s  by %s%s" % (
            self.name,
            self.version,
            self.digest[:12],
            self.publisher[:16] or "unsigned",
            "  [" + "; ".join(flags) + "]" if flags else "",
        )


class Conflict:
    """The same name and version published twice with different content."""

    __slots__ = ("spec", "entries")

    def __init__(self, spec: str, entries: Sequence[Mapping[str, Any]]) -> None:
        self.spec = spec
        self.entries = list(entries)

    def format(self) -> str:
        lines = ["%s was published %d times with different content:" % (self.spec, len(self.entries))]
        for item in self.entries:
            lines.append(
                "  #%-5s %s  digest %s  by %s"
                % (item["seq"], item["ts"], item["digest"][:12], item["publisher"][:16] or "unsigned")
            )
        return "\n".join(lines)


def fetch_source(source: str, timeout: float = 60.0) -> bytes:
    """Read an archive from a local path, a ``file://`` URL or over HTTPS."""
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"user-agent": "attestry"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as handle:
                data = handle.read(MAX_FETCH_BYTES + 1)
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise AttestryError("could not fetch %s: %s" % (source, exc))
        if len(data) > MAX_FETCH_BYTES:
            raise AttestryError("%s is larger than the %d MB fetch limit"
                                % (source, MAX_FETCH_BYTES // 1048576))
        return data
    path = source[7:] if source.startswith("file://") else source
    if not os.path.exists(path):
        raise AttestryError("no such file: %s" % path)
    with open(path, "rb") as handle:
        return handle.read()


class Registry:
    """Publish, resolve and install packages, using a ledger as the index."""

    def __init__(
        self,
        ledger: Ledger,
        trust: Optional[TrustStore] = None,
        cache_dir: str = "",
    ) -> None:
        self.ledger = ledger
        self.trust = trust
        self.cache_dir = cache_dir

    # -- publishing ------------------------------------------------------

    def publish(
        self,
        package: Package,
        sources: Optional[Sequence[str]] = None,
        key: Optional[KeyPair] = None,
    ) -> Any:
        """Record a package version in the ledger.

        Refuses to republish a version whose content differs from what the
        ledger already says that version is. Immutable versions are the reason
        a digest recorded in a lockfile keeps meaning something; allowing a
        silent overwrite would make every other guarantee here decorative.
        """
        problems = package.manifest.validate()
        if problems:
            raise AttestryError(
                "%s cannot be published:\n  - %s"
                % (package.manifest.spec, "\n  - ".join(problems))
            )
        digest = package.digest()
        for existing in self.publications(package.manifest.name, include_revoked=True):
            if existing.version != package.manifest.version:
                continue
            if existing.digest == digest:
                raise AttestryError(
                    "%s is already published with this exact content (entry #%d)"
                    % (package.manifest.spec, existing.seq)
                )
            raise ForkDetected(
                "%s was already published as %s at entry #%d, but this package "
                "hashes to %s. Published versions are immutable -- release a new "
                "version instead."
                % (package.manifest.spec, existing.digest[:12], existing.seq, digest[:12])
            )

        return self.ledger.append(
            "registry.publish",
            package.manifest.spec,
            {
                "name": package.manifest.name,
                "version": package.manifest.version,
                "digest": digest,
                "manifest": package.manifest.to_dict(),
                "files": [
                    {"path": path, "digest": file_digest, "exec": executable}
                    for path, file_digest, executable in package.file_digests()
                ],
                "bytes": package.total_bytes(),
                "sources": list(sources or []),
            },
            key=key,
        )

    def revoke(self, spec: str, reason: str, key: Optional[KeyPair] = None) -> Any:
        """Withdraw a published version. The original entry stays in the chain."""
        name, wanted = parse_spec(spec)
        matches = [p for p in self.publications(name, include_revoked=True)
                   if _satisfies(p.version, wanted)]
        if not matches:
            raise AttestryError("nothing published matching %r" % spec)
        target = max(matches, key=lambda p: version_key(p.version))
        return self.ledger.append(
            "registry.revoke",
            target.spec,
            {
                "name": target.name,
                "version": target.version,
                "digest": target.digest,
                "reason": reason,
                "revoked_at": now_rfc3339(),
            },
            key=key,
        )

    # -- reading ---------------------------------------------------------

    def publications(
        self, name: Optional[str] = None, include_revoked: bool = False
    ) -> List[Publication]:
        """Every publication in the ledger, newest last."""
        revocations: Dict[str, str] = {}
        for entry in self.ledger.entries():
            if entry.kind == "registry.revoke":
                revocations[entry.subject] = entry.body.get("reason", "")

        out: List[Publication] = []
        for entry in self.ledger.entries():
            if entry.kind != "registry.publish":
                continue
            body = entry.body
            if name and body.get("name") != name:
                continue
            try:
                manifest = Manifest.from_dict(body.get("manifest", {}))
            except Exception:
                continue
            publication = Publication(
                name=body.get("name", ""),
                version=body.get("version", ""),
                digest=body.get("digest", ""),
                manifest=manifest,
                publisher=entry.sig.split(":")[1] if entry.sig else "",
                seq=entry.seq,
                ts=entry.ts,
                sources=body.get("sources"),
                files=body.get("files"),
            )
            if publication.spec in revocations:
                publication.revoked = True
                publication.revoke_reason = revocations[publication.spec]
            self._apply_trust(publication, entry.ts)
            if publication.revoked and not include_revoked:
                continue
            out.append(publication)
        return out

    def _apply_trust(self, publication: Publication, ts: str) -> None:
        if self.trust is None:
            publication.trusted = True
            publication.trust_note = "no trust store configured; signatures unchecked"
            return
        if not publication.publisher:
            publication.trusted = False
            publication.trust_note = "publication is unsigned"
            return
        # Prefer the key material the ledger itself declares, exactly as chain
        # verification does. Without this, trust-on-first-use can never pin a
        # publisher: the key is sitting in a ledger.key-trusted entry, and
        # consulting only the local store reports it as unknown.
        public = self.ledger.key_table().get(publication.publisher)
        if public is None:
            known = self.trust.keys.get(publication.publisher)
            public = known["public"] if known else None
        ok, reason = self.trust.check(publication.publisher, public, ts)
        publication.trusted = ok
        publication.trust_note = reason

    def names(self) -> List[str]:
        return sorted({p.name for p in self.publications()})

    def resolve(self, spec: str, require_trusted: bool = True) -> Publication:
        """Find the best version matching ``spec``.

        Revoked versions are never resolved, and untrusted publishers are
        excluded unless you ask otherwise. The error messages distinguish "no
        such package", "no version matching that range" and "found it, but you
        do not trust who published it", because the fix differs in each case.
        """
        name, wanted = parse_spec(spec)
        candidates = self.publications(name)
        if not candidates:
            revoked = [p for p in self.publications(name, include_revoked=True)]
            if revoked:
                raise AttestryError(
                    "every published version of %s has been revoked (%s)"
                    % (name, revoked[-1].revoke_reason or "no reason given")
                )
            raise AttestryError("nothing published under the name %r" % name)

        matching = [p for p in candidates if _satisfies(p.version, wanted)]
        if not matching:
            available = ", ".join(sorted({p.version for p in candidates}, key=version_key))
            raise AttestryError(
                "no version of %s satisfies %r; available: %s" % (name, wanted, available)
            )

        if require_trusted:
            trusted = [p for p in matching if p.trusted]
            if not trusted:
                offender = max(matching, key=lambda p: version_key(p.version))
                raise TrustError(
                    "%s was published by %s, which you do not trust: %s. Add the "
                    "key with 'attestry ledger trust add' if you recognise it."
                    % (offender.spec, offender.publisher or "an unsigned entry",
                       offender.trust_note)
                )
            matching = trusted

        return max(matching, key=lambda p: version_key(p.version))

    def conflicts(self) -> List[Conflict]:
        """Specs published more than once with different content.

        In a synced, multi-writer ledger this is the signal that two publishers
        disagree about what a version is -- either a name collision or somebody
        trying to substitute content. It cannot be resolved automatically, so it
        is reported.
        """
        seen: Dict[str, List[Dict[str, Any]]] = {}
        for entry in self.ledger.entries():
            if entry.kind != "registry.publish":
                continue
            spec = entry.subject
            seen.setdefault(spec, []).append(
                {
                    "seq": entry.seq,
                    "ts": entry.ts,
                    "digest": entry.body.get("digest", ""),
                    "publisher": entry.sig.split(":")[1] if entry.sig else "",
                }
            )
        out = []
        for spec, entries in sorted(seen.items()):
            if len({item["digest"] for item in entries}) > 1:
                out.append(Conflict(spec, entries))
        return out

    # -- installing ------------------------------------------------------

    def install(
        self,
        spec: str,
        source: Optional[str] = None,
        destination: str = "",
        require_trusted: bool = True,
        key: Optional[KeyPair] = None,
    ) -> Tuple[Publication, str]:
        """Fetch, verify and unpack a package. Returns ``(publication, path)``.

        Verification happens entirely in memory, before a single byte is written
        to the destination. A package whose content does not hash to what the
        ledger says gets nowhere near the filesystem.
        """
        publication = self.resolve(spec, require_trusted=require_trusted)
        sources = [source] if source else list(publication.sources)
        if not sources:
            raise AttestryError(
                "%s has no recorded source to fetch from; pass one explicitly "
                "with --from" % publication.spec
            )

        errors = []
        package: Optional[Package] = None
        used = ""
        for candidate in sources:
            try:
                data = fetch_source(candidate)
                package = Package.from_archive_bytes(data)
                used = candidate
                break
            except AttestryError as exc:
                errors.append("%s: %s" % (candidate, exc))
        if package is None:
            raise AttestryError(
                "could not fetch %s from any recorded source:\n  - %s"
                % (publication.spec, "\n  - ".join(errors))
            )

        actual = package.digest()
        if actual != publication.digest:
            raise IntegrityError(
                "%s does not match the ledger: expected %s, the fetched archive "
                "hashes to %s. The source has been altered since publication."
                % (publication.spec, publication.digest[:16], actual[:16])
            )
        if (package.manifest.name, package.manifest.version) != (
            publication.name,
            publication.version,
        ):
            raise IntegrityError(
                "archive claims to be %s but the ledger recorded %s"
                % (package.manifest.spec, publication.spec)
            )

        target = destination or os.path.join(self.cache_dir or ".", actual)
        os.makedirs(target, exist_ok=True)
        package.write_dir(target)

        self.ledger.append(
            "registry.install",
            publication.spec,
            {
                "name": publication.name,
                "version": publication.version,
                "digest": actual,
                "source": used,
                "path": target,
                "publisher": publication.publisher,
            },
            key=key,
        )
        return publication, target

    def verify_installed(self, path: str, publication: Publication) -> Tuple[bool, str]:
        """Re-hash an installed directory and compare against the ledger."""
        try:
            package = Package.from_dir(path)
        except AttestryError as exc:
            return False, str(exc)
        actual = package.digest()
        if actual == publication.digest:
            return True, "matches the published digest"
        return False, "on disk hashes to %s, ledger says %s" % (
            actual[:16], publication.digest[:16]
        )
