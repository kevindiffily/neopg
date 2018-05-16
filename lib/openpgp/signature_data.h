// OpenPGP signature data
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>
#include <neopg/public_key_material.h>
#include <neopg/signature_material.h>
#include <neopg/signature_subpacket.h>

#include <array>
#include <memory>

namespace NeoPG {

enum class HashAlgorithm : uint8_t {
  Md5 = 1,
  Sha1 = 2,
  Ripemd160 = 3,
  Reserved_4 = 4,
  Reserved_5 = 5,
  Reserved_6 = 6,
  Reserved_7 = 7,
  Sha256 = 8,
  Sha384 = 9,
  Sha512 = 10,
  Sha224 = 11,
  Private_100 = 100,
  Private_101 = 101,
  Private_102 = 102,
  Private_103 = 103,
  Private_104 = 104,
  Private_105 = 105,
  Private_106 = 106,
  Private_107 = 107,
  Private_108 = 108,
  Private_109 = 109,
  Private_110 = 110
};

enum class SignatureVersion : uint8_t { V2 = 2, V3 = 3, V4 = 4 };

/// Represent an OpenPGP [signature
/// type](https://tools.ietf.org/html/rfc4880#section-5.2.1).
enum class NEOPG_UNSTABLE_API SignatureType : uint8_t {
  Binary = 0x00,
  Text = 0x01,
  Standalone = 0x02,
  UidGeneric = 0x10,
  UidPersona = 0x11,
  UidCasual = 0x12,
  UidPositive = 0x13,
  BindingSubkey = 0x18,
  BindingKey = 0x19,
  KeyDirect = 0x1f,
  RevokeKey = 0x20,
  RevokeSubkey = 0x28,
  RevokeUid = 0x30,
  Timestamp = 0x40,
  Confirmation = 0x50
};

/// Represent an OpenPGP [signature
/// packet](https://tools.ietf.org/html/rfc4880#section-5.2).
class NEOPG_UNSTABLE_API SignatureData {
 public:
  static std::unique_ptr<SignatureData> create_or_throw(
      SignatureVersion version, ParserInput& input);

  virtual void write(std::ostream& out) const = 0;

  virtual SignatureVersion version() const noexcept = 0;

  virtual SignatureType signature_type() const noexcept = 0;
  virtual PublicKeyAlgorithm public_key_algorithm() const noexcept = 0;
  virtual HashAlgorithm hash_algorithm() const noexcept = 0;
};

class NEOPG_UNSTABLE_API V2o3SignatureData : public SignatureData {
 public:
  // V2 and V3 signatures are identical but for the version number.
  SignatureVersion m_version;

  SignatureType m_type{SignatureType::Binary};
  uint32_t m_created{0};
  std::array<uint8_t, 8> m_signer{{0, 0, 0, 0, 0, 0, 0, 0}};
  PublicKeyAlgorithm m_public_key_algorithm{PublicKeyAlgorithm::Rsa};
  HashAlgorithm m_hash_algorithm{HashAlgorithm::Sha1};
  std::array<uint8_t, 2> m_quick{{0, 0}};
  std::unique_ptr<SignatureMaterial> m_signature;

  static std::unique_ptr<V2o3SignatureData> create_or_throw(
      SignatureVersion version, ParserInput& input);

  void write(std::ostream& out) const override;

  SignatureVersion version() const noexcept override { return m_version; }
  SignatureType signature_type() const noexcept override { return m_type; }
  PublicKeyAlgorithm public_key_algorithm() const noexcept override {
    return m_public_key_algorithm;
  }
  HashAlgorithm hash_algorithm() const noexcept override {
    return m_hash_algorithm;
  }
};

class NEOPG_UNSTABLE_API V4SignatureData : public SignatureData {
 public:
  SignatureType m_type{SignatureType::Binary};
  uint32_t m_created{0};
  PublicKeyAlgorithm m_public_key_algorithm{PublicKeyAlgorithm::Rsa};
  HashAlgorithm m_hash_algorithm{HashAlgorithm::Sha1};
  std::unique_ptr<SignatureMaterial> m_signature;
  std::vector<std::unique_ptr<SignatureSubpacket>> m_hashed_subpackets;
  std::vector<std::unique_ptr<SignatureSubpacket>> m_unhashed_subpackets;
  std::array<uint8_t, 2> m_quick{{0, 0}};

  static std::unique_ptr<V4SignatureData> create_or_throw(ParserInput& input);

  void write(std::ostream& out) const override;

  SignatureVersion version() const noexcept override {
    return SignatureVersion::V4;
  }
  SignatureType signature_type() const noexcept override { return m_type; }
  PublicKeyAlgorithm public_key_algorithm() const noexcept override {
    return m_public_key_algorithm;
  }
  HashAlgorithm hash_algorithm() const noexcept override {
    return m_hash_algorithm;
  }
};

}  // namespace NeoPG
