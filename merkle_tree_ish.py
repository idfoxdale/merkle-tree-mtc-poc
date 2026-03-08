# Merkle Tree Proof of Concept for Quantum-Resistant Certificates
#
# This script implements a simple Merkle Tree, demonstrating how it can be used
# to provide compact inclusion proofs for certificates. This approach reduces
# TLS handshake sizes from potentially 15KB+ down to around 700 bytes, helping
# make the web ready for post-quantum cryptography without sacrificing speed.
#
# Key Concepts:
# - Leaves: Hashes of certificate data
# - Nodes: Hashes of concatenated child pairs (using SHA-256)
# - Root: Single top hash representing the entire tree
# - Proof: Short path of sibling hashes allowing verification of inclusion
#
# Designed to be clear, educational, and easy to share. Run it to see the tree
# being built, proofs generated, verified, and how proof size stays small even
# as the number of certificates grows.
#
# Author: Isha
# License: MIT (feel free to use, modify, and share)

import hashlib
from typing import List, Tuple, Union

class MerkleTree:
    def __init__(self, leaves: List[Union[str, bytes]]):
        """
        Initialize the Merkle Tree with a list of leaves (e.g., certificate data).
        :param leaves: List of strings or bytes to hash as leaves.
        """
        if not leaves:
            raise ValueError("Leaves list cannot be empty")
        self.leaves = [self._hash_leaf(leaf) for leaf in leaves]
        self.tree = self._build_tree(self.leaves)

    def _hash_leaf(self, data: Union[str, bytes]) -> bytes:
        """Hash the leaf data using SHA-256."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).digest()

    def _hash_node(self, left: bytes, right: bytes = None) -> bytes:
        """Hash two child nodes. If no right child (odd count), return left."""
        if right is None:
            return left
        return hashlib.sha256(left + right).digest()

    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """Build the tree levels from leaves up to the root."""
        tree = [leaves[:]]  # Copy to avoid modifying original
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else None
                next_level.append(self._hash_node(left, right))
            tree.append(next_level)
            current_level = next_level
        return tree

    def get_root(self) -> str:
        """Return the hex string of the Merkle root hash."""
        return self.tree[-1][0].hex()

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Generate an inclusion proof for the leaf at the given index.
        :param index: 0-based index of the leaf.
        :return: List of (sibling_hash_hex, direction) where direction is 'left' or 'right'.
        """
        if not 0 <= index < len(self.leaves):
            raise ValueError("Index out of range")
        
        proof = []
        current_index = index
        for level in range(len(self.tree) - 1):
            is_left = current_index % 2 == 0
            sibling_index = current_index + 1 if is_left else current_index - 1
            if sibling_index < len(self.tree[level]):
                sibling = self.tree[level][sibling_index]
                direction = 'right' if is_left else 'left'
                proof.append((sibling.hex(), direction))
            current_index //= 2
        return proof

    def print_tree(self, abbreviate: bool = True) -> None:
        """Print a readable text representation of the tree."""
        print("Merkle Tree Structure (top to bottom):")
        for lvl, nodes in enumerate(reversed(self.tree)):
            level_str = f"Level {lvl}: "
            node_strs = [n.hex()[:8] + '...' if abbreviate else n.hex() for n in nodes]
            level_str += " | ".join(node_strs)
            print(level_str)

def verify_proof(leaf: Union[str, bytes], proof: List[Tuple[str, str]], root: str) -> bool:
    """
    Verify if the leaf is included in the tree given the proof and root.
    :param leaf: Original leaf data (str or bytes).
    :param proof: List from get_proof().
    :param root: Expected root hex string.
    :return: True if valid, False otherwise.
    """
    current = hashlib.sha256(leaf.encode('utf-8') if isinstance(leaf, str) else leaf).digest()
    for sibling_hex, direction in proof:
        sibling = bytes.fromhex(sibling_hex)
        if direction == 'left':
            current = hashlib.sha256(sibling + current).digest()
        elif direction == 'right':
            current = hashlib.sha256(current + sibling).digest()
        else:
            raise ValueError("Invalid direction in proof")
    return current.hex() == root

if __name__ == "__main__":
    # Example 1: Small tree with 4 certificates
    print("=== Example 1: Small Tree (4 Leaves) ===")
    small_certs = [
        "Cert1: example.com - Valid until 2030",
        "Cert2: google.com - Post-Quantum Ready",
        "Cert3: cloudflare.com - MTC Enabled",
        "Cert4: mydomain.com - Secured"
    ]
    mt_small = MerkleTree(small_certs)
    mt_small.print_tree()
    root_small = mt_small.get_root()
    print(f"\nRoot: {root_small[:16]}... (truncated)")

    index = 1  # Cert2
    proof_small = mt_small.get_proof(index)
    print(f"\nProof for index {index}:")
    for i, (h, d) in enumerate(proof_small):
        print(f"  Step {i+1}: {h[:16]}... ({d})")

    is_valid = verify_proof(small_certs[index], proof_small, root_small)
    print(f"Verification: {'Passed' if is_valid else 'Failed'}")

    proof_bytes = sum(len(bytes.fromhex(h)) for h, _ in proof_small)
    full_tree_bytes = sum(len(node) for level in mt_small.tree for node in level)
    print(f"Proof Size: {proof_bytes} bytes")
    print(f"Full Tree Size (approx): {full_tree_bytes} bytes")
    print(f"Efficiency: Proof is {full_tree_bytes / proof_bytes:.1f}x smaller\n")

    # Example 2: Larger tree with 16 leaves to show logarithmic scaling
    print("=== Example 2: Larger Tree (16 Leaves) ===")
    large_certs = [f"Cert{i+1}: domain{i+1}.com" for i in range(16)]
    mt_large = MerkleTree(large_certs)
    mt_large.print_tree()
    root_large = mt_large.get_root()
    print(f"\nRoot: {root_large[:16]}... (truncated)")

    index = 7  # Middle leaf
    proof_large = mt_large.get_proof(index)
    print(f"\nProof for index {index}:")
    for i, (h, d) in enumerate(proof_large):
        print(f"  Step {i+1}: {h[:16]}... ({d})")

    is_valid = verify_proof(large_certs[index], proof_large, root_large)
    print(f"Verification: {'Passed' if is_valid else 'Failed'}")

    proof_bytes = sum(len(bytes.fromhex(h)) for h, _ in proof_large)
    full_tree_bytes = sum(len(node) for level in mt_large.tree for node in level)
    print(f"Proof Size: {proof_bytes} bytes (logarithmic!)")
    print(f"Full Tree Size (approx): {full_tree_bytes} bytes")
    print(f"Efficiency: Proof is {full_tree_bytes / proof_bytes:.1f}x smaller")

    print("\nNote: For 1 billion certificates, the proof would still be only ~960 bytes!")