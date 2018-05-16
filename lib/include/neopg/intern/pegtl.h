// PEGTL support
// Copyright 2017 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/parser_error.h>
#include <neopg/parser_input.h>
#include <neopg/parser_position.h>

// Protect our use of PEGTL from other library users.
#define TAO_PEGTL_NAMESPACE neopg_pegtl
#include <tao/pegtl.hpp>

namespace pegtl = tao::TAO_PEGTL_NAMESPACE;

namespace NeoPG {

class ParserInput::Impl {
 public:
  pegtl::memory_input<> m_input;
  Impl(const char* data, size_t length) : m_input{data, length, "-"} {}
};

class ParserInput::Mark::Impl {
 public:
  pegtl::internal::marker<pegtl::internal::iterator,
                          pegtl::rewind_mode::REQUIRED>
      m_mark;
  Impl(ParserInput& in)
      : m_mark{in.m_impl->m_input.mark<pegtl::rewind_mode::REQUIRED>()} {}
};

template <typename Input>
ParserError parser_error(const std::string& msg, const Input& in) {
  const pegtl::position in_pos = in.position();
  ParserPosition pos(in_pos.source, in_pos.byte);
  return ParserError(msg, pos);
}

}  // namespace NeoPG
