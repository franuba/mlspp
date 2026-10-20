#include <mls_ds/tree_follower.h>

namespace MLS_NAMESPACE::mls_ds {

///
/// Resolving & Applying Proposals
///

using SenderAndProposal = std::tuple<Sender, Proposal>;

static std::vector<SenderAndProposal>
resolve(CipherSuite suite,
        Sender commit_sender,
        const std::vector<ProposalOrRef>& proposals,
        const std::vector<MLSMessage>& extra_proposals)
{
  auto cache = std::map<ProposalRef, SenderAndProposal>{};
  for (const auto& proposal_msg : extra_proposals) {
    const auto& public_message = var::get<PublicMessage>(proposal_msg.message);
    const auto content_auth = public_message.authenticated_content();
    const auto sender = content_auth.content.sender;
    const auto proposal = var::get<Proposal>(content_auth.content.content);

    const auto ref = suite.ref(content_auth);
    cache.insert_or_assign(ref, std::make_tuple(sender, proposal));
  }

  // Resolve the proposals vector
  return stdx::transform<SenderAndProposal>(
    proposals, [&](const auto& proposal_or_ref) {
      const auto resolver =
        overloaded{ [&](const Proposal& proposal) -> SenderAndProposal {
                     return { commit_sender, proposal };
                   },
                    [&](const ProposalRef& ref) -> SenderAndProposal {
                      return cache.at(ref);
                    } };
      return var::visit(resolver, proposal_or_ref.content);
    });
}

static void
apply(TreeKEMPublicKey& tree, Sender /* sender */, const Add& add)
{
  tree.add_leaf(add.key_package.leaf_node);
}

static void
apply(TreeKEMPublicKey& tree, Sender /* sender */, const Remove& remove)
{
  tree.blank_path(remove.removed);
}

static void
apply(TreeKEMPublicKey& tree, Sender sender, const Update& update)
{
  const auto sender_index = var::get<MemberSender>(sender.sender).sender;
  tree.update_leaf(sender_index, update.leaf_node);
}

static void
apply(TreeKEMPublicKey& /* tree */,
      Sender /* sender */,
      const PreSharedKey& /* pre_shared_key */)
{
}

static void
apply(TreeKEMPublicKey& /* tree */,
      Sender /* sender */,
      const ReInit& /* re_init */)
{
}

static void
apply(TreeKEMPublicKey& /* tree */,
      Sender /* sender */,
      const ExternalInit& /* external_init */)
{
}

static void
apply(TreeKEMPublicKey& /* tree */,
      Sender /* sender */,
      const GroupContextExtensions& /* gce */)
{
}

static void
apply(TreeKEMPublicKey& tree,
      const std::vector<SenderAndProposal>& proposals,
      Proposal::Type proposal_type)
{
  for (const auto& [sender_, proposal] : proposals) {
    const auto& sender = sender_;
    if (proposal.proposal_type() != proposal_type) {
      continue;
    }

    var::visit([&](const auto& pr) { apply(tree, sender, pr); },
               proposal.content);
  }
}

static void
apply(TreeKEMPublicKey& tree,
      CipherSuite suite,
      Sender commit_sender,
      const std::vector<ProposalOrRef>& proposals,
      const std::vector<MLSMessage>& extra_proposals)
{
  const auto resolved =
    resolve(suite, commit_sender, proposals, extra_proposals);

  apply(tree, resolved, ProposalType::update);
  apply(tree, resolved, ProposalType::remove);
  apply(tree, resolved, ProposalType::add);
}

///
/// TreeFollower
///

TreeFollower::TreeFollower(const KeyPackage& key_package)
  : _suite(key_package.cipher_suite)
  , _tree(key_package.cipher_suite)
{
  _tree.add_leaf(key_package.leaf_node);
  _tree.set_hash_all();
}

TreeFollower::TreeFollower(TreeKEMPublicKey tree)
  : _suite(tree.suite)
  , _tree(std::move(tree))
{
}

void
TreeFollower::update(const MLSMessage& commit_message,
                     const std::vector<MLSMessage>& extra_proposals)
{
  // Unwrap the Commit
  const auto& commit_public_message =
    var::get<PublicMessage>(commit_message.message);
  const auto commit_auth_content =
    commit_public_message.authenticated_content();
  const auto group_content = commit_auth_content.content;
  const auto& commit = var::get<Commit>(commit_auth_content.content.content);

  // Apply proposals
  apply(_tree, _suite, group_content.sender, commit.proposals, extra_proposals);
  _tree.truncate();
  _tree.set_hash_all();

  // Merge the update path
  if (commit.path) {
    const auto sender = var::get<MemberSender>(group_content.sender.sender);
    const auto from = LeafIndex(sender.sender);
    const auto& path = opt::get(commit.path);
    _tree.merge(from, path);
  }
}

///
/// SplitCommit (draft-mularczyk-mls-splitcommit)
///

static std::tuple<Sender, SHeader>
unframe_sheader(const FramedSHeader& framed)
{
  if (!var::holds_alternative<PublicMessage>(framed.message)) {
    throw InvalidParameterError(
      "SplitCommit: only public SHeader framing is supported");
  }

  const auto& content_auth =
    var::get<PublicMessage>(framed.message).authenticated_content();
  return { content_auth.content.sender,
           var::get<SHeader>(content_auth.content.content) };
}

static LeafIndex
commit_sender(const Sender& sender)
{
  if (!var::holds_alternative<MemberSender>(sender.sender)) {
    throw InvalidParameterError(
      "SplitCommit: only member committers are supported");
  }

  return var::get<MemberSender>(sender.sender).sender;
}

void
TreeFollower::update(const SCommit& scommit,
                     const std::vector<MLSMessage>& extra_proposals)
{
  const auto [sender, sheader] = unframe_sheader(scommit.sheader);

  // Apply the proposals from the SHeader
  apply(_tree, _suite, sender, sheader.proposals, extra_proposals);
  _tree.truncate();
  _tree.set_hash_all();

  // Merge the update path; the committer's LeafNode rides in the SHeader
  if (scommit.path) {
    if (!sheader.leaf_node) {
      throw ProtocolError("SCommit with path but no SHeader leaf_node");
    }

    const auto from = commit_sender(sender);
    const auto& s_path = opt::get(scommit.path);
    _tree.merge(from, UpdatePath{ opt::get(sheader.leaf_node), s_path.nodes });
  }
}

ICommit
TreeFollower::split(const SCommit& scommit, LeafIndex receiver) const
{
  const auto [sender, sheader] = unframe_sheader(scommit.sheader);

  // A commit with no path needs no splitting: every receiver gets the SHeader
  if (!scommit.path) {
    return ICommit{ scommit.sheader, std::nullopt };
  }

  // The committer holds every key on its own path
  const auto from = commit_sender(sender);
  if (from == receiver) {
    return ICommit{ scommit.sheader, std::nullopt };
  }

  if (!sheader.leaf_node) {
    throw ProtocolError("SCommit with path but no SHeader leaf_node");
  }
  const auto& s_path = opt::get(scommit.path);

  // Find the common ancestor in the committer's post-commit direct path.  The
  // path nodes below it are the keys the receiver cannot derive from the
  // decrypted ancestor path secret; the ancestor index aligns with the
  // filtered direct path that indexes SUpdatePath::nodes.
  const auto ancestor = _tree.ancestor_index(receiver, from);
  if (ancestor.ancestor_node_index > s_path.nodes.size()) {
    throw ProtocolError("UpdatePath shorter than committer direct path");
  }

  // The ciphertext the receiver decrypts at the common ancestor (this is the
  // same lookup the resolution code uses to find the decryption node)
  const auto path = UpdatePath{ opt::get(sheader.leaf_node), s_path.nodes };
  const auto ciphertext =
    std::get<0>(_tree.slice_path(path, from, receiver));

  auto new_pks = std::vector<HPKEPublicKey>{};
  new_pks.reserve(ancestor.ancestor_node_index);
  for (auto i = size_t(0); i < ancestor.ancestor_node_index; i++) {
    new_pks.push_back(s_path.nodes.at(i).public_key);
  }

  return ICommit{
    scommit.sheader, IUpdatePath{ ciphertext, std::move(new_pks) }
  };
}

} // namespace MLS_NAMESPACE::mls_ds
