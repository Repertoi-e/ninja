#pragma once

#include <functional>

#include "state.h"

namespace cppm {
void scanner_update_state(
    State* state, const std::vector<Node*>& targets,
    const std::function<int(const std::vector<Node*>&)>& build_func);
void scanner_clean();
int scanner_run_tool(std::string_view tool_name);
}  // namespace cppm