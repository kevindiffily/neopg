// OpenPGP signature subpacket
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/packet.h>

#include <memory>
#include <vector>

namespace NeoPG {

enum class NEOPG_UNSTABLE_API SignatureSubpacketLengthType : uint8_t {
  OneOctet = 0,
  TwoOctet = 1,
  FiveOctet = 2,

  /// This picks the best encoding automatically.
  Default
};

class NEOPG_UNSTABLE_API SignatureSubpacketLength {
 public:
  SignatureSubpacketLengthType m_length_type;
  uint32_t m_length;

  static void verify_length(uint32_t length,
                            SignatureSubpacketLengthType length_type);

  static SignatureSubpacketLengthType best_length_type(uint32_t length);

  void set_length(uint32_t length, SignatureSubpacketLengthType length_type =
                                       SignatureSubpacketLengthType::Default);

  SignatureSubpacketLength(uint32_t length,
                           SignatureSubpacketLengthType length_type =
                               SignatureSubpacketLengthType::Default);

  void write(std::ostream& out);
};

/// Represent an OpenPGP [signature
/// subpacket type](https://tools.ietf.org/html/rfc4880#section-5.2.3.1).
enum class NEOPG_UNSTABLE_API SignatureSubpacketType : uint8_t {
  Reserved_0 = 0,
  Reserved_1 = 1,
  SignatureCreationTime = 2,
  SignatureExpirationTime = 3,
  ExportableCertification = 4,
  TrustSignature = 5,
  RegularExpression = 6,
  Revocable = 7,
  Reserved_8 = 8,
  KeyExpirationTime = 9,
  Placeholder_10 = 10,
  PreferredSymmetricAlgorithms = 11,
  RevocationKey = 12,
  Reserved_13 = 13,
  Reserved_14 = 14,
  Reserved_15 = 15,
  Issuer = 16,
  Reserved_17 = 17,
  Reserved_18 = 18,
  Reserved_19 = 19,
  NotationData = 20,
  PreferredHashAlgorithms = 21,
  PreferredCompressionAlgorithms = 22,
  KeyServerPreferences = 23,
  PreferredKeyServer = 24,
  PrimaryUserId = 25,
  PolicyUri = 26,
  KeyFlags = 27,
  SignersUserId = 28,
  ReasonForRevocation = 29,
  Features = 30,
  SignatureTarget = 31,
  EmbeddedSignature = 32,
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
  // Maximum is 127 (Bit 7 is the "critical" bit).
};

/// Represent an OpenPGP [signature
/// subpacket](https://tools.ietf.org/html/rfc4880#section-5.2.3.1).
class NEOPG_UNSTABLE_API SignatureSubpacket {
 public:
  static std::unique_ptr<SignatureSubpacket> create_or_throw(
      SignatureSubpacketType type, ParserInput& in);

  bool m_critical{false};
  std::unique_ptr<SignatureSubpacketLength> m_length;

  void write(std::ostream& out) const;
  virtual void write_body(std::ostream& out) const = 0;
  uint32_t body_length() const;
  virtual SignatureSubpacketType type() const noexcept = 0;
  bool critical() const noexcept { return m_critical; }
};

class NEOPG_UNSTABLE_API RawSignatureSubpacket : public SignatureSubpacket {
 public:
  static std::unique_ptr<SignatureSubpacket> create_or_throw(
      SignatureSubpacketType type, ParserInput& input);

  SignatureSubpacketType m_type{SignatureSubpacketType::Reserved_0};
  std::string m_content;

  void write_body(std::ostream& out) const override {
    out.write(reinterpret_cast<const char*>(m_content.data()),
              m_content.size());
  }
  SignatureSubpacketType type() const noexcept override { return m_type; }
  RawSignatureSubpacket(SignatureSubpacketType type, std::string content)
      : m_type(type), m_content(content) {}
};

// Subpacket type 2
class NEOPG_UNSTABLE_API SignatureCreationTimeSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<SignatureCreationTimeSubpacket> create_or_throw(
      ParserInput& input);

  uint32_t m_created;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::SignatureCreationTime;
  }
};

// Subpacket type 3
class NEOPG_UNSTABLE_API SignatureExpirationTimeSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<SignatureExpirationTimeSubpacket> create_or_throw(
      ParserInput& input);

  uint32_t m_expiration;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::SignatureExpirationTime;
  }
};

// Subpacket type 4
class NEOPG_UNSTABLE_API ExportableCertificationSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<ExportableCertificationSubpacket> create_or_throw(
      ParserInput& input);

  uint8_t m_exportable;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::ExportableCertification;
  }
};

// Subpacket type 5
class NEOPG_UNSTABLE_API TrustSignatureSubpacket : public SignatureSubpacket {
 public:
  static std::unique_ptr<TrustSignatureSubpacket> create_or_throw(
      ParserInput& input);

  uint8_t m_level;
  uint8_t m_amount;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::TrustSignature;
  }
};

// Subpacket type 6
class NEOPG_UNSTABLE_API RegularExpressionSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<RegularExpressionSubpacket> create_or_throw(
      ParserInput& input);

  std::string m_regex;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::RegularExpression;
  }
};

// Subpacket type 9
class NEOPG_UNSTABLE_API KeyExpirationTimeSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<KeyExpirationTimeSubpacket> create_or_throw(
      ParserInput& input);

  uint32_t m_expiration;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::KeyExpirationTime;
  }
};

class NEOPG_UNSTABLE_API PreferredSymmetricAlgorithmsSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<PreferredSymmetricAlgorithmsSubpacket> create_or_throw(
      ParserInput& input);

  std::vector<uint8_t> m_algorithms;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::PreferredSymmetricAlgorithms;
  }
};

class NEOPG_UNSTABLE_API IssuerSubpacket : public SignatureSubpacket {
 public:
  static std::unique_ptr<IssuerSubpacket> create_or_throw(ParserInput& input);

  std::vector<uint8_t> m_issuer;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::Issuer;
  }
};

class NEOPG_UNSTABLE_API PreferredHashAlgorithmsSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<PreferredHashAlgorithmsSubpacket> create_or_throw(
      ParserInput& input);

  std::vector<uint8_t> m_algorithms;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::PreferredHashAlgorithms;
  }
};

class NEOPG_UNSTABLE_API PreferredCompressionAlgorithmsSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<PreferredCompressionAlgorithmsSubpacket>
  create_or_throw(ParserInput& input);

  std::vector<uint8_t> m_algorithms;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::PreferredCompressionAlgorithms;
  }
};

class NEOPG_UNSTABLE_API KeyServerPreferencesSubpacket
    : public SignatureSubpacket {
 public:
  static std::unique_ptr<KeyServerPreferencesSubpacket> create_or_throw(
      ParserInput& input);

  std::vector<uint8_t> m_features;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::KeyServerPreferences;
  }
};

class NEOPG_UNSTABLE_API PrimaryUserIdSubpacket : public SignatureSubpacket {
 public:
  static std::unique_ptr<PrimaryUserIdSubpacket> create_or_throw(
      ParserInput& input);

  uint8_t m_primary;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::PrimaryUserId;
  }
};

class NEOPG_UNSTABLE_API KeyFlagsSubpacket : public SignatureSubpacket {
 public:
  static std::unique_ptr<KeyFlagsSubpacket> create_or_throw(ParserInput& input);

  uint8_t m_flags;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::KeyFlags;
  }
};

class NEOPG_UNSTABLE_API FeaturesSubpacket : public SignatureSubpacket {
 public:
  static std::unique_ptr<FeaturesSubpacket> create_or_throw(ParserInput& input);

  std::vector<uint8_t> m_features;

  void write_body(std::ostream& out) const override;
  SignatureSubpacketType type() const noexcept override {
    return SignatureSubpacketType::Features;
  }
};

}  // namespace NeoPG
