#include "scanner_plugin.h"
#include "cmd_line_utils.h"
#include "graph.h"
#include "scanner.h"
#include "trace.h"

#include <filesystem>
#include <iostream>
#include <unordered_set>

#include <fmt/format.h>

namespace fs = std::filesystem;

namespace cppm {

std::string get_ifc_path(std::string_view cmd) {
  fs::path cl_path = get_command_line_argument(cmd, 0);  // todo:
  cl_path.remove_filename();
  fs::path arch = cl_path.parent_path().filename();
  return (cl_path / "../../../ifc" / arch).string();
}

std::string get_bmi_file(std::string_view output_file) {
  return fs::path{ output_file }.replace_extension(".ifc").string();
}

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
    std::cout << "why don't we have source inputs ?\n";
  }
  return out_node;
}

void scanner_update_state(State* state) {
  TRACE();

  ModuleVisitor module_visitor;

  // todo: find which targets are for generated headers, build them first
  Scanner::Config config;
  config.submit_previous_results = true;
  config.module_visitor = &module_visitor;
  config.tool_path = R"(c:\Program Files\LLVM\bin\clang-scan-deps.exe)"; // todo:
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
  auto nr_edges = scan_item_idx_t{ state->edges_.size() };
  item_to_edge.reserve(nr_edges);
  item_to_src_node.reserve(nr_edges);
  item_to_out_node.reserve(nr_edges);

  for (Edge* edge : state->edges_) {
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

  vector_map<scan_item_idx_t, Node*> bmi_nodes;
  bmi_nodes.resize(config.item_set.items.size());
  for (auto i : config.item_set.items.indices())
    if (module_visitor.has_export[i])
      bmi_nodes[i] =
          state->GetNode(get_bmi_file(item_to_out_node[i]->path()), 0);

  fmt::memory_buffer cmd_buf;
  std::vector<Node*> implicit_inputs;
  for (auto idx : config.item_set.items.indices()) {
    bool has_export = (module_visitor.has_export[idx]);
    bool has_import = (!module_visitor.imports_item[idx].empty());
    if (!has_export && !has_import)
      continue;

    Edge* edge = item_to_edge[idx];
    cmd_buf.clear();
    implicit_inputs.clear();

    if (has_export || has_import) {
      auto cmd_idx = config.item_set.items[idx].command_idx;
      std::string ifcdir = get_ifc_path(config.item_set.commands[cmd_idx]);
      fmt::format_to(cmd_buf, " /experimental:module /module:stdIfcDir \"{}\"",
                     ifcdir);
    }
    if (has_export) {
      fmt::format_to(cmd_buf, " /module:interface /module:output \"{}\"", bmi_nodes[idx]->path());
	  // note: this requires disabling the assert(edge->outputs_.size() == 1) in build.cc 
      edge->outputs_.push_back(bmi_nodes[idx]); 
      edge->implicit_outs_++;
      bmi_nodes[idx]->set_in_edge(edge);
    }

    // it's enough to depend only on the direct imports
    // but the compiler still needs to know the paths to all of transitively
    // imported modules
    for (auto imp_idx : module_visitor.imports_item[idx]) {
      implicit_inputs.push_back(bmi_nodes[imp_idx]);
      bmi_nodes[imp_idx]->AddOutEdge(edge);
    }
    module_visitor.visit_transitive_imports(idx, [&](scan_item_idx_t imp_idx) {
      fmt::format_to(cmd_buf, " /module:reference \"{}\"",
                     bmi_nodes[imp_idx]->path());
    });

    if (cmd_buf.size() > 0) {
      edge->command_suffix_.resize(cmd_buf.size());
      memcpy(&edge->command_suffix_[0], cmd_buf.data(), cmd_buf.size());
    }

    if (!implicit_inputs.empty()) {
      std::size_t poz = edge->inputs_.size() - edge->order_only_deps_;
      edge->inputs_.insert(edge->inputs_.begin() + poz, implicit_inputs.begin(),
                           implicit_inputs.end());
      edge->implicit_deps_ += implicit_inputs.size();
    }
  }

  // exit(1);
}

}  // namespace cppm