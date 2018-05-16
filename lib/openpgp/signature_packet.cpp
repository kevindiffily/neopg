// OpenPGP signature packet (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_packet.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace signature_packet {
using namespace pegtl;

struct version : must<any> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<version> {
  template <typename Input>
  static void apply(const Input& in, SignatureVersion& version) {
    version = static_cast<SignatureVersion>(in.peek_byte());
  }
};

}  // namespace signature_packet
}  // namespace NeoPG

std::unique_ptr<SignaturePacket> SignaturePacket::create(ParserInput& in) {
  try {
    return SignaturePacket::create_or_throw(in);
  } catch (const pegtl::parse_error&) {
    return nullptr;
  }
}

std::unique_ptr<SignaturePacket> SignaturePacket::create_or_throw(
    ParserInput& in) {
  SignatureVersion version;
  pegtl::parse<signature_packet::version, signature_packet::action>(
      in.m_impl->m_input, version);

  auto packet = make_unique<SignaturePacket>(version);
  packet->m_signature = SignatureData::create_or_throw(version, in);
  return packet;
}

void SignaturePacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_version);
  if (m_signature) m_signature->write(out);
}
