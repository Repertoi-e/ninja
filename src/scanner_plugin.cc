#include "scanner_plugin.h"

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
  Node* src_node = nullptr;
  for (Node* node : edge->inputs_) {
    // cc rules depend on a phony rule for their target:
    if (node->in_edge() != nullptr)
      continue;
    if (src_node != nullptr) {
      std::cout << "why do we have two source inputs ?\n";
      break;
    }
    src_node = node;
  }
  if (src_node == nullptr) {
    std::cout << "why don't we have source inputs ?\n";
  }
  return src_node;
}

Node* get_out_node(Edge* edge) {
  Node* out_node = nullptr;
  for (Node* node : edge->outputs_) {
    if (out_node != nullptr) {
      std::cout << "why do we have two outputs ?\n";
      break;
    }
    out_node = node;
  }
  if (out_node == nullptr) {
    std::cout << "why don't we have source outputs ?\n";
  }
  return out_node;
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
    const vector_map<scan_item_idx_t, Scanner::Result>& results)
{
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

void scanner_update_state(State* state) {
  TRACE();

  // todo: find which targets are for generated headers, build them first
  std::vector<header_unit> header_units;
  Scanner::Config config;
  config.tool_path = R"(c:\Program Files\LLVM\bin\clang-scan-deps.exe)";
  if (!read_config(config, header_units))
    return;

  ModuleVisitor module_visitor;
  config.submit_previous_results = true;
  config.module_visitor = &module_visitor;
  config.db_path = fs::current_path().string();
  config.int_dir = config.db_path;
  config.item_set.commands.reserve(cmd_idx_t{ state->edges_.size() });
  config.item_set.commands_contain_item_path = true;
  config.item_set.items.reserve(scan_item_idx_t{ state->edges_.size() });
  config.item_set.targets.push_back("x");
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

  constexpr std::string_view rule_prefix = "CXX_COMPILER__";

  for (Edge* edge : state->edges_) {
    auto& rule_name = edge->rule().name();
    // todo: maybe use the config file or a special binding on the edge ?
    if (!starts_with(rule_name, rule_prefix))  // todo: use starts_with in C++20
      continue;
    // auto target = std::string_view{ rule_name }.substr(rule_prefix.size());

    Node* src_node = get_src_node(edge);
    Node* out_node = get_out_node(edge);
    if (!src_node || !out_node)
      continue;

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
    std::cerr << "scanner failed: " << e.what() << "\n";
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

}  // namespace cppm