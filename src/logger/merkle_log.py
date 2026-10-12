"""
Simple append-only Merkle-tree log for benchmarking comparison.
"""
import hashlib


class MerkleLog:
    def __init__(self):
        self.leaves = []

    @staticmethod
    def _hash(left: bytes, right: bytes) -> bytes:
        return hashlib.sha512(left + right).digest()

    def append(self, content: bytes) -> bytes:
        leaf = hashlib.sha512(content).digest()
        self.leaves.append(leaf)
        return leaf

    def root(self) -> bytes:
        if not self.leaves:
            return b"\x00" * 64
        level = list(self.leaves)
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level) - 1, 2):
                nxt.append(self._hash(level[i], level[i + 1]))
            if len(level) % 2 == 1:
                nxt.append(level[-1])
            level = nxt
        return level[0]
