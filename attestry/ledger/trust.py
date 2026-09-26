"""Who you accept signatures from.

A signature that verifies mathematically only tells you the holder of some key
made it. Trust is the separate question of whether that key is one you meant to
accept, and it is the question centralised registries answer for you by owning
the server. Attestry has no server, so it answers it locally and explicitly.

Three modes, because different situations genuinely want different answers:

``strict``
    Only key ids you added by hand are accepted. Correct for CI, for anything
    consuming skills from strangers, and for an auditor checking your receipts.

``tofu``
    Trust on first use. An unknown key is accepted the first time it appears and
    pinned; if the public key behind that id ever changes, it is rejected loudly.
    This is what SSH does with host keys, and it is the honest default for a
    single developer who does not want a ceremony before their first commit.

``open``
    Signature maths is checked, trust is not. Useful while developing, never in
    CI. Recorded in the store so ``attestry doctor`` can tell you about it.

Revocation carries a deliberate choice too. When a key is revoked because it was
rotated, everything it signed beforehand is still good (``invalidates: after``).
When it was revoked because it leaked, you cannot believe anything it ever
signed, because an attacker holding the key could have backdated entries
(``invalidates: all``). Getting this wrong in either direction is harmful, so
Attestry refuses to guess and makes ``attestry ledger revoke`` ask.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple

from ..util.errors import TrustError
from ..util.timeutil import now_rfc3339, parse_rfc3339
from .keys import KeyPair, keyid_for

__all__ = ["TrustStore", "MODES", "INVALIDATES"]

MODES = ("strict", "tofu", "open")
INVALIDATES = ("after", "all")


class TrustStore:
    """The set of keys this machine accepts, persisted as one JSON file."""

    def __init__(self, path: str, mode: str = "tofu") -> None:
        if mode not in MODES:
            raise ValueError("trust mode must be one of %s" % (", ".join(MODES),))
        self.path = path
        self.mode = mode
        self.keys: Dict[str, Dict[str, Any]] = {}
        self.revoked: Dict[str, Dict[str, Any]] = {}
        if os.path.exists(path):
            self.load()

    # -- persistence -----------------------------------------------------

    def load(self) -> "TrustStore":
        with open(self.path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.mode = data.get("mode", self.mode)
        self.keys = data.get("keys", {})
        self.revoked = data.get("revoked", {})
        return self

    def save(self) -> None:
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = {"mode": self.mode, "keys": self.keys, "revoked": self.revoked}
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

    # -- membership ------------------------------------------------------

    def add(self, public_hex: str, label: str = "", note: str = "") -> str:
        """Trust a public key. Returns its key id."""
        try:
            raw = bytes.fromhex(public_hex)
        except ValueError:
            raise TrustError("public key is not hex: %r" % (public_hex[:24],))
        if len(raw) != 32:
            raise TrustError(
                "an ed25519 public key is 32 bytes, got %d" % len(raw)
            )
        kid = keyid_for(public_hex)
        existing = self.keys.get(kid)
        if existing and existing["public"] != public_hex:
            # Cannot happen unless SHA-256 broke, but if it ever does, failing
            # loudly beats silently overwriting a trusted key.
            raise TrustError("key id collision for %s" % kid)
        self.keys[kid] = {
            "public": public_hex,
            "label": label or (existing or {}).get("label", ""),
            "note": note or (existing or {}).get("note", ""),
            "added": (existing or {}).get("added") or now_rfc3339(),
        }
        self.save()
        return kid

    def add_keypair(self, key: KeyPair, note: str = "") -> str:
        return self.add(key.public, key.label, note)

    def remove(self, keyid: str) -> bool:
        if keyid in self.keys:
            del self.keys[keyid]
            self.save()
            return True
        return False

    def revoke(self, keyid: str, reason: str, invalidates: str = "after") -> None:
        """Mark a key as no longer acceptable.

        ``invalidates="after"`` keeps prior signatures valid (routine rotation).
        ``invalidates="all"`` rejects everything the key ever signed (compromise).
        """
        if invalidates not in INVALIDATES:
            raise ValueError("invalidates must be 'after' or 'all'")
        self.revoked[keyid] = {
            "at": now_rfc3339(),
            "reason": reason,
            "invalidates": invalidates,
        }
        self.save()

    # -- the question everything else asks -------------------------------

    def check(
        self, keyid: str, public_hex: Optional[str] = None, signed_at: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Is a signature from ``keyid`` acceptable? Returns ``(ok, reason)``.

        ``public_hex`` is the key material the ledger offered for this id, when
        the ledger carries it. ``signed_at`` is the entry timestamp, needed to
        decide whether a revocation applies to it.
        """
        revocation = self.revoked.get(keyid)
        if revocation:
            if revocation.get("invalidates") == "all":
                return False, "key %s is revoked (%s), all its signatures rejected" % (
                    keyid,
                    revocation.get("reason", "no reason recorded"),
                )
            if signed_at and self._signed_after(signed_at, revocation.get("at", "")):
                return False, "key %s was revoked before this entry was signed" % keyid

        known = self.keys.get(keyid)
        if known:
            if public_hex and known["public"] != public_hex:
                return False, (
                    "key %s does not match the pinned public key; either the "
                    "ledger is lying about the key or your trust store is stale"
                    % keyid
                )
            return True, "trusted"

        if self.mode == "strict":
            return False, (
                "key %s is not in the trust store; add it with "
                "'attestry ledger trust add' if you recognise it" % keyid
            )
        if self.mode == "open":
            return True, "trust checks disabled (mode=open)"

        # tofu: pin it now, reject any later change.
        if public_hex:
            self.add(public_hex, label="", note="pinned on first use")
            return True, "pinned on first use"
        return False, "key %s is unknown and the ledger carries no key material" % keyid

    @staticmethod
    def _signed_after(signed_at: str, revoked_at: str) -> bool:
        """Was this signature made after the key was revoked?

        Ledger timestamps have second precision, so a signature made in the same
        second as a revocation is genuinely ambiguous. It is given the benefit of
        the doubt, because this comparison only ever runs for
        ``invalidates: after`` -- routine rotation, where the old signatures are
        meant to stay valid and wrongly rejecting one breaks a working ledger.

        Nothing is lost by being lenient here. The case where you cannot trust
        the timing at all is key compromise, and ``invalidates: all`` covers it
        by rejecting every signature from the key regardless of when it claims
        to have been made.
        """
        if not revoked_at:
            return False
        try:
            return parse_rfc3339(signed_at) > parse_rfc3339(revoked_at)
        except ValueError:
            # An unparseable timestamp is treated as after the revocation: when
            # in doubt about time, do not accept the signature.
            return True

    def describe(self) -> str:
        lines = ["trust mode: %s" % self.mode, "trusted keys: %d" % len(self.keys)]
        for kid, info in sorted(self.keys.items()):
            lines.append(
                "  %s  %s%s"
                % (kid, info.get("label") or "(unlabelled)",
                   "  [" + info["note"] + "]" if info.get("note") else "")
            )
        if self.revoked:
            lines.append("revoked keys: %d" % len(self.revoked))
            for kid, info in sorted(self.revoked.items()):
                lines.append(
                    "  %s  %s (invalidates %s)"
                    % (kid, info.get("reason", ""), info.get("invalidates", "after"))
                )
        return "\n".join(lines)
