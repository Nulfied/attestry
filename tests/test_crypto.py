"""Canonical JSON, Merkle trees, Ed25519 and key handling.

These are the load-bearing pieces: if canonicalisation is not deterministic or a
Merkle proof can be forged, nothing built on top means anything.
"""

from __future__ import annotations

import hashlib
import unittest

from attestry.ledger import keys as keymod
from attestry.ledger import ed25519 as pure
from attestry.ledger import merkle
from attestry.util.canonical import canonical_json, digest_of

# The first three test vectors from RFC 8032 section 7.1.
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
        "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_does_not_change_the_digest(self) -> None:
        self.assertEqual(
            digest_of({"a": 1, "b": {"c": 2, "d": 3}}),
            digest_of({"b": {"d": 3, "c": 2}, "a": 1}),
        )

    def test_no_whitespace_and_sorted_keys(self) -> None:
        self.assertEqual(canonical_json({"b": 1, "a": [1, 2]}), '{"a":[1,2],"b":1}')

    def test_int_and_float_stay_distinguishable(self) -> None:
        self.assertEqual(canonical_json(1), "1")
        self.assertEqual(canonical_json(1.0), "1.0")
        self.assertNotEqual(digest_of({"v": 1}), digest_of({"v": 1.0}))

    def test_non_finite_floats_are_rejected(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                canonical_json(value)

    def test_non_string_keys_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            canonical_json({1: "a"})

    def test_unserialisable_values_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            canonical_json({"v": object()})

    def test_unicode_is_not_escaped(self) -> None:
        self.assertEqual(canonical_json({"k": "café"}), '{"k":"café"}')

    def test_control_characters_are_escaped(self) -> None:
        self.assertIn("\\n", canonical_json("a\nb"))

    def test_tuples_and_lists_agree(self) -> None:
        self.assertEqual(digest_of({"v": [1, 2]}), digest_of({"v": (1, 2)}))


class MerkleTests(unittest.TestCase):
    @staticmethod
    def leaves(count: int) -> list:
        return [hashlib.sha256(bytes([i])).hexdigest() for i in range(count)]

    def test_every_proof_verifies_for_many_tree_sizes(self) -> None:
        for size in range(1, 34):
            leaves = self.leaves(size)
            root = merkle.root_hex(leaves)
            for index in range(size):
                path = merkle.path_hex(leaves, index)
                self.assertTrue(
                    merkle.verify_path_hex(leaves[index], index, size, path, root),
                    "size %d index %d should verify" % (size, index),
                )

    def test_wrong_index_is_rejected(self) -> None:
        leaves = self.leaves(7)
        root = merkle.root_hex(leaves)
        path = merkle.path_hex(leaves, 3)
        self.assertFalse(merkle.verify_path_hex(leaves[3], 4, 7, path, root))

    def test_truncated_and_padded_paths_are_rejected(self) -> None:
        leaves = self.leaves(9)
        root = merkle.root_hex(leaves)
        path = merkle.path_hex(leaves, 5)
        self.assertFalse(merkle.verify_path_hex(leaves[5], 5, 9, path[:-1], root))
        self.assertFalse(
            merkle.verify_path_hex(leaves[5], 5, 9, path + [leaves[0]], root)
        )

    def test_wrong_leaf_is_rejected(self) -> None:
        leaves = self.leaves(5)
        root = merkle.root_hex(leaves)
        path = merkle.path_hex(leaves, 2)
        self.assertFalse(merkle.verify_path_hex(leaves[1], 2, 5, path, root))

    def test_leaf_and_node_hashes_are_domain_separated(self) -> None:
        # Without distinct prefixes an internal node could be replayed as a leaf.
        blob = b"x" * 32
        self.assertNotEqual(merkle.leaf_hash(blob), merkle.node_hash(blob[:16], blob[16:]))

    def test_empty_tree_has_a_defined_root(self) -> None:
        self.assertEqual(merkle.merkle_root([]), hashlib.sha256(b"").digest())


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors_pure_python(self) -> None:
        for secret_hex, public_hex, message_hex, signature_hex in RFC8032:
            secret = bytes.fromhex(secret_hex)
            message = bytes.fromhex(message_hex)
            self.assertEqual(pure.secret_to_public(secret).hex(), public_hex)
            self.assertEqual(pure.sign(secret, message).hex(), signature_hex)
            self.assertTrue(
                pure.verify(bytes.fromhex(public_hex), message, bytes.fromhex(signature_hex))
            )

    def test_tampered_message_fails(self) -> None:
        secret = bytes.fromhex(RFC8032[1][0])
        public = pure.secret_to_public(secret)
        signature = pure.sign(secret, b"hello")
        self.assertFalse(pure.verify(public, b"hellp", signature))

    def test_malformed_input_returns_false_rather_than_raising(self) -> None:
        self.assertFalse(pure.verify(b"short", b"m", b"0" * 64))
        self.assertFalse(pure.verify(b"0" * 32, b"m", b"short"))

    def test_non_canonical_s_is_rejected(self) -> None:
        # s must be reduced mod the group order; a larger value would allow the
        # same message to verify under two different encodings.
        secret = bytes.fromhex(RFC8032[1][0])
        public = pure.secret_to_public(secret)
        signature = bytearray(pure.sign(secret, b"m"))
        signature[32:] = (2 ** 255 - 1).to_bytes(32, "little")
        self.assertFalse(pure.verify(public, b"m", bytes(signature)))

    def test_backends_interoperate(self) -> None:
        """Whichever backend is active must agree with the bundled one."""
        secret = bytes.fromhex(RFC8032[2][0])
        message = b"cross-backend"
        active = keymod._raw_sign(secret, message)
        reference = pure.sign(secret, message)
        self.assertEqual(active, reference)
        public = keymod._public_from_secret(secret)
        self.assertTrue(pure.verify(public, message, active))
        self.assertTrue(keymod._raw_verify(public, message, reference))


class KeyTests(unittest.TestCase):
    def test_keyid_is_stable_and_domain_separated(self) -> None:
        key = keymod.generate("a")
        self.assertEqual(key.keyid, keymod.keyid_for(key.public))
        self.assertEqual(len(key.keyid), 16)
        self.assertNotEqual(key.keyid, hashlib.sha256(bytes.fromhex(key.public)).hexdigest()[:16])

    def test_sign_and_verify_round_trip(self) -> None:
        key = keymod.generate("a")
        signature = keymod.sign_bytes(key, b"payload")
        self.assertTrue(keymod.verify_bytes(signature, b"payload", key.public))
        self.assertFalse(keymod.verify_bytes(signature, b"other", key.public))

    def test_signature_bound_to_its_keyid(self) -> None:
        """A valid signature must not verify while naming a different identity."""
        one, two = keymod.generate("one"), keymod.generate("two")
        signature = keymod.sign_bytes(one, b"payload")
        swapped = signature.replace(one.keyid, two.keyid)
        self.assertFalse(keymod.verify_bytes(swapped, b"payload", two.public))

    def test_public_only_key_cannot_sign(self) -> None:
        from attestry.util.errors import TrustError

        key = keymod.generate("a").public_only()
        self.assertFalse(key.can_sign)
        with self.assertRaises(TrustError):
            keymod.sign_bytes(key, b"x")

    def test_public_only_never_serialises_the_secret(self) -> None:
        key = keymod.generate("a")
        self.assertNotIn("secret", key.to_dict())
        self.assertIn("secret", key.to_dict(include_secret=True))
        self.assertIsNone(key.public_only().secret)


if __name__ == "__main__":
    unittest.main()
