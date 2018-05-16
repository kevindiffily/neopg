// OpenPGP parser error
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains support for parser errors.

#pragma once

#include <neopg/common.h>
#include <neopg/parser_position.h>

#include <memory>
#include <string>

namespace NeoPG {

class NEOPG_UNSTABLE_API ParserError : public std::runtime_error {
 public:
  ParserError(const std::string& msg, ParserPosition& pos)
      : std::runtime_error(pos.as_string() + ":" + msg), m_pos(pos) {}

  ParserPosition m_pos;
};

}  // namespace NeoPG
