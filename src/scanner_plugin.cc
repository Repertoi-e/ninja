#include "scanner_plugin.h"

#include <algorithm>
#include <fstream>
#include <iostream>

#include "graph.h"
#include "module_cmdgen.h"
#include "scanner.h"
#include "trace.h"

namespace fs = std::filesystem;

namespace cppm {

void adjust_command(std::string& cmd) {
  // showincludes causes the scanner to print deps in MSVC format which breaks
  // the output parsing
  std::string_view showincludes = " /showIncludes";
  auto ofs = cmd.find(showincludes);
  if (ofs != std::string::npos)
    cmd.erase(ofs, showincludes.size());
}

Node* get_src_node(Edge* edge) {
  assert(edge != nullptr);
  assert(!edge->inputs_.empty());
  return edge->inputs_.front();
}

struct EdgeUpdater {
  Edge* edge;
  std::vector<Node*> new_implicit_inputs, new_explicit_inputs,
      new_explicit_outputs;
  std::size_t explicit_input_end = 0, implicit_input_end = 0,
              explicit_output_end = 0;

  void set_edge_to_update(Edge* e) {
    edge = e;
    new_implicit_inputs.clear();
    new_explicit_inputs.clear();
    new_explicit_outputs.clear();
    implicit_input_end = edge->inputs_.size() - edge->order_only_deps_;
    explicit_input_end = implicit_input_end - edge->implicit_deps_;
    explicit_output_end = edge->outputs_.size() - edge->implicit_outs_;
  }

  void add_explicit_input(Node* new_input) {
    new_explicit_inputs.push_back(new_input);
    new_input->AddOutEdge(edge);
  }

  void add_implicit_input(Node* new_input) {
    new_implicit_inputs.push_back(new_input);
    new_input->AddOutEdge(edge);
    edge->implicit_deps_++;
  }

  void add_explicit_output(Node* new_output) {
    new_explicit_outputs.push_back(new_output);
    new_output->set_in_edge(edge);
  }

  void add_implicit_output(Node* new_output) {
    edge->outputs_.push_back(new_output);
    edge->implicit_outs_++;
    new_output->set_in_edge(edge);
  }

  void insert(std::vector<Node*>& dst, const std::vector<Node*>& src,
              std::size_t ofs) {
    if (!src.empty())
      dst.insert(dst.begin() + ofs, src.begin(), src.end());
  }

  void update() {
    insert(edge->inputs_, new_explicit_inputs, explicit_input_end);
    insert(edge->inputs_, new_implicit_inputs,
           implicit_input_end + new_explicit_inputs.size());
    insert(edge->outputs_, new_explicit_outputs, explicit_output_end);
  }
};

std::pair<std::string_view, std::string_view> split_in_two(
    std::string_view str, std::string_view delim) {
  auto first = str.substr(0, str.find(delim));
  auto second = str.substr(std::min(first.size() + 1, str.size()));
  return { first, second };
}

struct header_unit {
  std::string target;
  std::string src_path;
};

bool read_config(Scanner::Config& config,
                 std::vector<header_unit>& header_units) {
  TRACE();
  std::ifstream fin("scanner_config.txt");
  if (!fin)
    return false;
  std::string line_buf;
  while (std::getline(fin, line_buf)) {
    std::string_view line = line_buf;
    auto [key, value] = split_in_two(line, " ");
    if (key == "tool_path") {
      config.tool_path = (std::string)value;
    } else if (key == "header_unit") {
      auto [target, headers] = split_in_two(value, " ");
      while (!headers.empty()) {
        auto [header, remaining] = split_in_two(headers, ";");
        header_units.push_back({ (std::string)target, (std::string)header });
        headers = remaining;
      }
    }
  }
  return true;
}

void add_header_unit(State* state, std::string_view target,
                     std::string_view header) {
  // todo: currently unused, but will be needed for e.g clang modules
  std::string rule_name = "CXX_COMPILER__";
  rule_name += target;
  const Rule* rule = state->bindings_.LookupRule(rule_name);
  if (!rule)
    throw std::invalid_argument(
        fmt::format("could not find rule {}", rule_name));
  Node* node = state->LookupNode(StringPiece{ header.data(), header.size() });
  assert(node != nullptr);
  Edge* edge = state->AddEdge(rule);
  edge->inputs_.push_back(node);
}

inline bool ends_with(std::string_view str, std::string_view with) {
  if (str.size() < with.size())
    return false;
  return str.substr(str.size() - with.size(), with.size()) == with;
}

inline bool starts_with(std::string_view str, std::string_view with) {
  if (str.size() < with.size())
    return false;
  return str.substr(0, with.size()) == with;
}

bool print_results(
    const vector_map<scan_item_idx_t, Scanner::Result>& results) {
  uint32_t utd_items = 0;
  uint32_t scanned_items = 0;
  uint32_t failed_items = 0;
  for (auto& r : results) {
    if (r.ood == ood_state::up_to_date)
      utd_items++;
    else
      scanned_items++;
    if (r.scan == scan_state::failed)
      failed_items++;
  }

  fmt::print("scanned {} items, {} up-to-date", scanned_items, utd_items);
  if (failed_items != 0)
    fmt::print(", {} failed", failed_items);
  fmt::print("\n");
  return failed_items == 0;
}

// When a source file X depends on generated headers from a previous target Y,
// CMake generates a node with the cmake_object_order_depends prefix
// and X will depend on that order only node, which then depends on Y.

// If you have A with inputs B and C, but C has an order only dependency on D
// which then has B as an input, then a single BFS traversal is not enough.
// The ninja generator could make sure that this doesn't happen, but then
// if the user wants to build multiple targets then we have the same problem.
struct GraphWalker {
 public:
  std::vector<Node*> queue;
  std::vector<std::pair<Node*, int>> old_ids;
  std::vector<Node*> order_only;
  std::vector<Node*> cpp_objects;

  GraphWalker(State* state) {
    std::size_t nr_edges = state->edges_.size();
    queue.reserve(nr_edges);
    old_ids.reserve(nr_edges);
    order_only.reserve(nr_edges);
    cpp_objects.reserve(nr_edges);
  }

  bool is_cpp_object(Node* out_node) {
    Edge* edge = out_node->in_edge();
    if (!edge)
      return false;
    // todo: maybe use the config file or a special binding on the edge ?
    // todo: use string::starts_with in C++20
    return starts_with(edge->rule().name(), "CXX_COMPILER__");
  }

  template <int id_visited, bool save_old_ids>
  void add_to_queue(Node* node) {
    queue.push_back(node);
    if constexpr (save_old_ids)
      old_ids.push_back({ node, node->id() });
    node->set_id(id_visited);
  }

  template <int id_visited, bool save_old_ids>
  void queue_inputs(Node* node) {
    Edge* in_edge = node->in_edge();
    if (!in_edge)
      return;
    for (Node* input : in_edge->inputs_) {
      if (input->id() == id_visited)
        continue;
      add_to_queue<id_visited, save_old_ids>(input);
    }
  }

  // Find a set of order only nodes such that if you build that set,
  // the generated headers will be available when scanning everything else.
  // At the same time, find a set that contains all sources to be scanned.
  // In both cases, this is not necessarily the minimal set yet,
  // some might get removed later.
  // Setting the node id to -2 is used to mark a node as visited. This
  // assumes ninja doesn't already assign negative values other than -1
  // to any of the node ids. The nodes might already have an id, so that id
  // is saved and will be restored later.
  void find_order_only_nodes(const std::vector<Node*>& targets) {
    for (Node* node : targets)
      add_to_queue<-2, true>(node);

    std::size_t s = 0;
    while (s < queue.size()) {
      Node* node = queue[s++];
      if (is_cpp_object(node)) {
        cpp_objects.push_back(node);
      } else if (starts_with(node->path(), "cmake_object_order_depends")) {
        order_only.push_back(node);
      }
      queue_inputs<-2, true>(node);
    }
  }

  // Mark every traansitive dependency of the order only nodes.
  // The previous step already visited all the nodes, so we don't need
  // to add any additional ids to be restored later.
  void find_pre_scan_nodes() {
    queue.clear();

    // don't add the order only nodes themselves to the queue,
    // they will only be marked and added to the queue if
    // they are the transitive dependency of another order only node
    for (Node* node : order_only)
      queue_inputs<-3, false>(node);

    std::size_t s = 0;
    while (s < queue.size())
      queue_inputs<-3, false>(queue[s++]);
  }

  // todo: use std::erase_if in C++20
  template <typename Pred>
  void erase_if(std::vector<Node*>& vec, Pred&& pred) {
    vec.erase(std::remove_if(vec.begin(), vec.end(), std::forward<Pred>(pred)),
              vec.end());
  }

  void remove_pre_scan_nodes() {
    auto is_pre_scan_node = [](Node* node) { return node->id() == -3; };
    erase_if(order_only, is_pre_scan_node);
    erase_if(cpp_objects, is_pre_scan_node);
  }

  void restore_node_ids() {
    for (auto [node, id] : old_ids)
      node->set_id(id);
  }

  void get_pre_scan_targets_and_sources_to_scan(
      const std::vector<Node*>& targets) {
    TRACE();

    find_order_only_nodes(targets);
    find_pre_scan_nodes();
    remove_pre_scan_nodes();
    restore_node_ids();
  }
};

void scanner_update_state(
    State* state, const vector<Node*>& targets,
    const std::function<int(const std::vector<Node*>&)>& build_func) {
  std::vector<header_unit> header_units;
  Scanner::Config config;
  config.tool_path = R"(c:\Program Files\LLVM\bin\clang-scan-deps.exe)";
  if (!read_config(config, header_units))
    return;

  for (Node* target : targets) {
    // no need to scan if we're going to clean everything
    if (target->path() == "clean")
      return;
  }

  GraphWalker walker{ state };
  // Find which targets are for generated headers, build them before scanning.
  // Only scan sources which have not been built already.
  // todo: the ninja generator could do this partitioning already,
  // so this may be pretty fast but there's no need to do it on every build
  walker.get_pre_scan_targets_and_sources_to_scan(targets);

#if 0
  for (Node* target : walker.order_only) {
    fmt::print("{}\n", target->path());
  }
  exit(1);
#endif

  if (int ret = build_func(walker.order_only); ret != 0)
    exit(ret);

  TRACE();

  ModuleVisitor module_visitor;
  config.submit_previous_results = true;
  config.module_visitor = &module_visitor;
  config.db_path = fs::current_path().string();
  config.int_dir = config.db_path;
  config.item_set.commands.reserve(cmd_idx_t{ state->edges_.size() });
  config.item_set.commands_contain_item_path = true;
  config.item_set.items.reserve(scan_item_idx_t{ state->edges_.size() });
  config.item_set.targets.push_back("x");  // todo:
  config.item_set.item_root_path = config.db_path;

  vector_map<scan_item_idx_t, Edge*> item_to_edge;
  vector_map<scan_item_idx_t, Node*> item_to_src_node;
  vector_map<scan_item_idx_t, Node*> item_to_out_node;
  vector_map<scan_item_idx_t, ModuleCommandGenerator::Format> item_cmd_format;
  auto nr_edges = scan_item_idx_t{ state->edges_.size() };
  item_to_edge.reserve(nr_edges);
  item_to_src_node.reserve(nr_edges);
  item_to_out_node.reserve(nr_edges);
  item_cmd_format.reserve(nr_edges);

  for (Node* out_node : walker.cpp_objects) {
    Edge* edge = out_node->in_edge();
    Node* src_node = get_src_node(edge);
    // auto target = std::string_view{ rule_name }.substr(rule_prefix.size());
    bool is_header_unit = ends_with(src_node->path(), ".h");  // todo:

    config.item_set.items.push_back({ src_node->path(),
                                      config.item_set.commands.size(),
                                      {},  // todo: use target
                                      is_header_unit });

    std::string cmd = edge->EvaluateCommand(/*incld_rs_file=*/true);
    adjust_command(cmd);
    config.item_set.commands.push_back(cmd);
    item_to_edge.push_back(edge);
    item_to_src_node.push_back(src_node);
    item_to_out_node.push_back(out_node);
    // todo: maybe use a config file or this, or a special binding on the edge ?
    item_cmd_format.push_back(ModuleCommandGenerator::detect_format(cmd));
  }

  auto config_owned_view = Scanner::ConfigOwnedView::from(config);
  auto config_view = Scanner::ConfigView::from(config_owned_view);

  Scanner scanner;
  try {
    if (!print_results(scanner.scan(config_view)))
      exit(1);
  } catch (std::exception& e) {
    fmt::print("scanner failed: {}\n", e.what());
    exit(1);
  }

  ModuleCommandGenerator cmd_gen{ config_view.item_set, module_visitor };
  vector_map<scan_item_idx_t, Node*> bmi_nodes;
  bmi_nodes.resize(config.item_set.items.size());
  for (auto i : config.item_set.items.indices())
    if (config.item_set.items[i].is_header_unit ||
        !module_visitor.exports[i].empty())
      bmi_nodes[i] =
          state->GetNode(cmd_gen.get_bmi_file(item_to_out_node[i]->path()), 0);

  EdgeUpdater edge_updater;
  for (auto idx : config.item_set.items.indices()) {
    bool is_header_unit = config.item_set.items[idx].is_header_unit;
    bool has_export = (!module_visitor.exports[idx].empty());
    bool has_import = (!module_visitor.imports_item[idx].empty());
    if (!is_header_unit && !has_export && !has_import)
      continue;

    Edge* obj_edge = item_to_edge[idx];
    edge_updater.set_edge_to_update(obj_edge);

    auto format = item_cmd_format[idx];
    cmd_gen.generate(idx, format, [&](scan_item_idx_t idx) -> std::string_view {
      return bmi_nodes[idx]->path();
    });

    if (format.isClang()) {
      // clang builds the bmi and the obj separately
      cmd_gen.references_to_string(obj_edge->command_suffix_);
      if (has_export || is_header_unit) {
        edge_updater.add_implicit_input(bmi_nodes[idx]);
        edge_updater.update();

        Edge* bmi_edge = state->AddEdge(&obj_edge->rule());
        bmi_edge->env_ = obj_edge->env_;
        cmd_gen.full_cmd_to_string(bmi_edge->command_suffix_);
        edge_updater.set_edge_to_update(bmi_edge);
        edge_updater.add_explicit_input(item_to_src_node[idx]);
        edge_updater.add_explicit_output(bmi_nodes[idx]);
        // note: the inputs for the module imports will be added to the bmi
        // edge instead of the object edge
      }
    } else if (format.isMSVC()) {
      // MSVC builds both the bmi and the obj in one command
      cmd_gen.full_cmd_to_string(obj_edge->command_suffix_);
      if (has_export || is_header_unit) {
        // note: this requires disabling the assert(edge->outputs_.size() == 1)
        // in build.cc
        edge_updater.add_implicit_output(bmi_nodes[idx]);
      }
    }

    // it's enough to depend only on the direct imports
    // but the compiler still needs to know the paths to all of transitively
    // imported modules
    for (auto imp_idx : module_visitor.imports_item[idx])
      edge_updater.add_implicit_input(bmi_nodes[imp_idx]);

    edge_updater.update();
  }

  // exit(1);
}

void scanner_clean() {
  Scanner scanner;
  try {
    scanner.clean_all(fs::current_path().string());
  } catch (std::exception& e) {
    std::cerr << "clean failed: " << e.what() << "\n";
    exit(1);
  }
}

}  // namespace cppm