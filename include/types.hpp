#pragma once
#include <vector>
#include "span.hpp"

using byte_t     = char;
using bytes      = std::vector<byte_t>;
using bytes_view = span<const byte_t>;