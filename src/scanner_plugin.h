#pragma once

#include "state.h"
#include <functional>

namespace cppm {
void scanner_update_state(State* state, const std::vector<Node*>& targets,
	const std::function<int(const std::vector<Node*>&)>& build_func);
void scanner_clean();
} // namespace cppm