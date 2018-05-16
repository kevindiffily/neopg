// OpenPGP signature packet
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>
#include <neopg/signature_data.h>

#include <memory>

namespace NeoPG {

/// Represent an OpenPGP [signature
/// packet](https://tools.ietf.org/html/rfc4880#section-5.2).
class NEOPG_UNSTABLE_API SignaturePacket : public Packet {
 public:
  static std::unique_ptr<SignaturePacket> create_or_throw(ParserInput& input);
  static std::unique_ptr<SignaturePacket> create(ParserInput& input);

  SignatureVersion m_version;
  std::unique_ptr<SignatureData> m_signature;

  void write_body(std::ostream& out) const override;
  PacketType type() const override { return PacketType::Signature; };

  SignaturePacket(SignatureVersion version) : m_version{version} {}
};

}  // namespace NeoPG
