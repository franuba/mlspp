#pragma once

#include <mls/messages.h>
#include <mls/treekem.h>
#include <vector>

namespace MLS_NAMESPACE::mls_ds {

using namespace MLS_NAMESPACE;

class TreeFollower
{
public:
  // Construct a one-member tree
  TreeFollower(const KeyPackage& key_package);

  // Import a tree as a starting point for future updates
  TreeFollower(TreeKEMPublicKey tree);

  // Update the tree with a set of proposals applied by a commit
  void update(const MLSMessage& commit_message,
              const std::vector<MLSMessage>& extra_proposals);

  // Update the tree from a SplitCommit SCommit (draft-mularczyk-mls-splitcommit
  // §3): apply the SHeader's proposals, then merge the SUpdatePath with the
  // committer's LeafNode from the SHeader.  Only public SHeader framing and
  // member committers are supported.
  void update(const SCommit& scommit,
              const std::vector<MLSMessage>& extra_proposals = {});

  // Split a previously applied SCommit into the ICommit for `receiver`
  // (draft §7.2): the SHeader plus the one HPKE ciphertext the receiver
  // decrypts at the common ancestor, and the path public keys below the
  // ancestor that the receiver cannot derive.  The tracked tree must already
  // reflect `scommit`, i.e., update(scommit, ...) must have been called first.
  ICommit split(const SCommit& scommit, LeafIndex receiver) const;

  // Accessors
  CipherSuite cipher_suite() const { return _suite; }
  const TreeKEMPublicKey& tree() const { return _tree; }

private:
  CipherSuite _suite;
  TreeKEMPublicKey _tree;
};

} // namespace MLS_NAMESPACE::mls_ds
