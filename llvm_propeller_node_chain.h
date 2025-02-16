#ifndef AUTOFDO_LLVM_PROPELLER_NODE_CHAIN_H_
#define AUTOFDO_LLVM_PROPELLER_NODE_CHAIN_H_

#include <algorithm>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "llvm_propeller_cfg.h"
#include "third_party/abseil/absl/container/flat_hash_set.h"

// A node chain represents an ordered list of CFG nodes, which are further
// splitted into multiple (ordered) list of nodes called bundles. For example
//
//   * bundle1 {foo -> foo.1} -> bundle2 {bar} -> bundle3 {foo.2 -> foo.3}
//
// represents a chain for 4 nodes from function "foo" and one node from "bar".
// The nodes are grouped into three bundles: two bundles for "foo" and one
// bundle for "bar".
// NodeChainBuilder keeps merging chains together to form longer chains.
// Merging may be done by splitting one chains and shoving the other chain
// in between, but it cannot break any bundles. For instance, the chain above
// can only be splitted across the two bundle-joining parts (bundle1 and bundle2
// or bundle2 and bundle3). NodeChainBuilder can also "bundle-up" multiple
// bundles into a single bundle when no gains are foreseen from splitting those
// bundles.
//
// At each point in time, every node belongs to exactly one bundle which is
// contained in exactly one chain.

namespace devtools_crosstool_autofdo {

class NodeChain;

class CFGNodeBundle {
 public:
  // All the CFG nodes in this bundle.
  std::vector<CFGNode *> nodes_;

  // Containing chain for this bundle.
  NodeChain *chain_;

  // Offset at which this bundle is located in its containing chain.
  int64_t chain_offset_;

  // Total binary size of this bundle.
  uint64_t size_;

  // Total execution frequency of this bundle.
  uint64_t freq_;

  // Constructor for building a bundle for a single CFG node and placing it in a
  // given chain.
  CFGNodeBundle(CFGNode *n, NodeChain *c, int64_t chain_offset)
      : nodes_(1, n),
        chain_(c),
        chain_offset_(chain_offset),
        size_(n->size()),
        freq_(n->freq()) {
    n->set_bundle(this);
  }
};

// Represents a chain of nodes (basic blocks).
class NodeChain {
 public:
  // Representative node for the chain.
  CFGNode *delegate_node_;

  // ControlFlowGraph of the nodes in this chain (This will be null if the nodes
  // come from more than one cfg).
  ControlFlowGraph *cfg_;

  // Ordered list of the bundles of the chain.
  std::vector<std::unique_ptr<CFGNodeBundle>> node_bundles_;
  // Total binary size of the chain.
  uint64_t size_;
  // Total execution frequency of the chain.
  uint64_t freq_;

  struct PtrComparator {
    bool operator()(const NodeChain *nc1, const NodeChain *nc2) const {
      if (!nc2) return false;
      if (!nc1) return true;
      return nc1->id() < nc2->id();
    }
  };

  // Each map key is a NodeChain which has (at least) one CFGNode that is
  // the sink end of one of the "inter_outs_" of CFGNode in "this" NodeChain,
  // the corresponding map value is the collection of CFGNodes which have
  // "inter_outs_"'s sink end equals to one of the CFGNodes of the corresponding
  // map key.
  // Note, we use "NodeChain::PtrComparator" to make sure the iterating order is
  // deterministic.
  std::map<NodeChain *, std::vector<CFGEdge *>, NodeChain::PtrComparator>
      out_edges_;

  // Chains which have outgoing edges to this chain. Using "unordered_set"
  // implies we never iterate this set (because iterating order is
  // undeterministic), we only search it.
  absl::flat_hash_set<NodeChain *> in_edges_;

  uint64_t id() const { return delegate_node_->symbol_ordinal(); }

  // Gives the execution density for this chain.
  double exec_density() const {
    return (static_cast<double>(freq_)) /
           std::max(size_, static_cast<uint64_t>(1));
  }

  // Constructor for building a chain from a single node, placed in one bundle
  // of its own.
  explicit NodeChain(CFGNode *node) {
    node_bundles_.emplace_back(new CFGNodeBundle(node, this, 0));
    delegate_node_ = node;
    cfg_ = node->cfg();
    size_ = node->size();
    freq_ = node->freq();
  }

  // This moves the bundles from another chain into this chain and updates the
  // bundle and chain fields accordingly. After this is called, the 'other'
  // chain becomes empty.
  void MergeWith(NodeChain *other) {
    for (auto &bundle : other->node_bundles_) {
      bundle->chain_ = this;
      bundle->chain_offset_ += size_;
    }
    std::move(other->node_bundles_.begin(), other->node_bundles_.end(),
              std::back_inserter(node_bundles_));
    size_ += other->size_;
    freq_ += other->freq_;
    // Nullify cfg_ if the other chain's nodes come from a different CFG.
    if (cfg_ && cfg_ != other->cfg_)
      cfg_ = nullptr;
  }

  CFGNode * GetFirstNode() {
    return node_bundles_.front()->nodes_.front();
  }

  // Helper function to iterate over the outgoing edges of this chain to a
  // specific chain, while applying a given function on each edge.
  template <class Visitor>
  void VisitEachOutEdgeToChain(NodeChain *chain, Visitor v) {
    auto it = out_edges_.find(chain);
    if (it == out_edges_.end()) return;
    for (CFGEdge *e : it->second)
      v(*e);
  }

  // Visit each candidate chain of this chain. This includes all the chains
  // that this chain has edges to or from, excluding itself.
  template <class Visitor>
  void VisitEachCandidateChain(Visitor v) {
    // Visit chains having edges *to* this chain.
    for (auto *c : in_edges_) {
      if (c == this) continue;
      v(c);
    }
    // Visit chains having *from* this chain, excluding those visited above.
    for (auto &elem : out_edges_) {
      if (elem.first == this) continue;
      // Chains having edges *to* this chain are already visited above.
      if (in_edges_.count(elem.first)) continue;
      v(elem.first);
    }
  }

  // Helper method for iterating over all nodes in this chain (in order).
  template <class Visitor>
  void VisitEachNodeRef(Visitor v) {
    for (auto &bundle_ptr : node_bundles_)
      for (CFGNode *n : bundle_ptr->nodes_) v(*n);
  }
};

// Gets the chain containing a given node.
NodeChain *GetNodeChain(const CFGNode *n);

// Gets the offset of a node in its containing chain.
int64_t GetNodeOffset(const CFGNode *n);

}  // namespace devtools_crosstool_autofdo

#endif  // AUTOFDO_LLVM_PROPELLER_NODE_CHAIN_H_
