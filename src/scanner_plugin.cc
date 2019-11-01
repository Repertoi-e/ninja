#include "scanner_plugin.h"
#include "graph.h"
#include "scanner.h"
#include "trace.h"

#include <fstream>
#include <iostream>

#include "module_cmdgen.h"

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

void read_config(Scanner::Config& config) {
  std::ifstream fin("scanner_config.txt");
  std::string line_buf;
  while (std::getline(fin, line_buf)) {
    std::string_view line = line_buf;
    auto key = line.substr(0, line.find(" "));
    auto value = line.substr(std::min(key.size() + 1, line.size()));
    if (key == "tool_path") {
      config.tool_path = (std::string)value;
    }
  }
}

void scanner_update_state(State* state) {
  TRACE();

  ModuleVisitor module_visitor;

  // todo: find which targets are for generated headers, build them first
  Scanner::Config config;
  config.submit_previous_results = true;
  config.module_visitor = &module_visitor;
  config.tool_path =
      R"(c:\Program Files\LLVM\bin\clang-scan-deps.exe)";
  config.db_path = fs::current_path().string();
  config.int_dir = config.db_path;

  config.item_set.commands.reserve(cmd_idx_t{ state->edges_.size() });
  config.item_set.commands_contain_item_path = true;
  config.item_set.items.reserve(scan_item_idx_t{ state->edges_.size() });
  config.item_set.targets.push_back("x");
  config.item_set.item_root_path = config.db_path;

  read_config(config);

  vector_map<scan_item_idx_t, Edge*> item_to_edge;
  vector_map<scan_item_idx_t, Node*> item_to_src_node;
  vector_map<scan_item_idx_t, Node*> item_to_out_node;
  vector_map<scan_item_idx_t, ModuleCommandGenerator::Format> item_cmd_format;
  auto nr_edges = scan_item_idx_t{ state->edges_.size() };
  item_to_edge.reserve(nr_edges);
  item_to_src_node.reserve(nr_edges);
  item_to_out_node.reserve(nr_edges);
  item_cmd_format.reserve(nr_edges);

  for (Edge* edge : state->edges_) {
    // todo: maybe use a config file or this, or a special binding on the edge ?
    if (edge->rule().name().find("CXX_COMPILER") != 0)
      continue;
    Node* src_node = get_src_node(edge);
    Node* out_node = get_out_node(edge);
    if (!src_node || !out_node)
      continue;
    config.item_set.items.push_back(
        { src_node->path(), config.item_set.commands.size(), {} });
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
    scanner.scan(config_view);
  } catch (std::exception& e) {
    std::cerr << "scanner failed: " << e.what() << "\n";
    exit(1);
  }

  ModuleCommandGenerator cmd_gen{ config_view.item_set, module_visitor };
  vector_map<scan_item_idx_t, Node*> bmi_nodes;
  bmi_nodes.resize(config.item_set.items.size());
  for (auto i : config.item_set.items.indices())
    if (!module_visitor.exports[i].empty())
      bmi_nodes[i] =
          state->GetNode(cmd_gen.get_bmi_file(item_to_out_node[i]->path()), 0);

  EdgeUpdater edge_updater;
  for (auto idx : config.item_set.items.indices()) {
    bool has_export = (!module_visitor.exports[idx].empty());
    bool has_import = (!module_visitor.imports_item[idx].empty());
    if (!has_export && !has_import)
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
      if (has_export) {
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
      if (has_export) {
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