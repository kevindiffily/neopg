// OpenPGP public key material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/multiprecision_integer.h>
#include <neopg/object_identifier.h>
#include <neopg/parser_input.h>

#include <memory>

namespace NeoPG {

/// Public key [algorithm
/// specifier](https://tools.ietf.org/html/rfc4880#section-9.1).
enum class PublicKeyAlgorithm : uint8_t {
  Rsa = 1,
  RsaEncrypt = 2,
  RsaSign = 3,
  ElgamalEncrypt = 16,
  Dsa = 17,
  Ecdh = 18,
  Ecdsa = 19,
  Elgamal = 20,
  DhX942 = 21,
  Eddsa = 22,
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

/// Algorithm-specific key material for a [public
/// key](https://tools.ietf.org/html/rfc4880#section-5.5.2).
class NEOPG_UNSTABLE_API PublicKeyMaterial {
 public:
  /// Create an instance based on the algorithm.
  /// @param algorithm algorithm specifier
  /// @param input parser input with key material
  /// Throws parse_error if input can not be parsed.
  static std::unique_ptr<PublicKeyMaterial> create_or_throw(
      PublicKeyAlgorithm algorithm, ParserInput& input);

  /// @return the algorithm specifier
  virtual PublicKeyAlgorithm algorithm() const = 0;

  /// Write the key material to the output stream.
  /// @param out output stream
  virtual void write(std::ostream& out) const = 0;
};

/// Key material for RSA public keys.
class NEOPG_UNSTABLE_API RsaPublicKeyMaterial : public PublicKeyMaterial {
 public:
  MultiprecisionInteger m_n;
  MultiprecisionInteger m_e;

  static std::unique_ptr<RsaPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Rsa;
  };

  void write(std::ostream& out) const override;
};

/// Key material for DSA public keys.
class NEOPG_UNSTABLE_API DsaPublicKeyMaterial : public PublicKeyMaterial {
 public:
  MultiprecisionInteger m_p;
  MultiprecisionInteger m_q;
  MultiprecisionInteger m_g;
  MultiprecisionInteger m_y;  // g**x mod p (x secret)

  static std::unique_ptr<DsaPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Dsa;
  };

  void write(std::ostream& out) const override;
};

/// Key material for Elgamal public keys.
class NEOPG_UNSTABLE_API ElgamalPublicKeyMaterial : public PublicKeyMaterial {
 public:
  MultiprecisionInteger m_p;
  MultiprecisionInteger m_g;
  MultiprecisionInteger m_y;  // g**x mod p (x secret)

  static std::unique_ptr<ElgamalPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Elgamal;
  };

  void write(std::ostream& out) const override;
};

/// Key material for [Ecdsa public
/// keys](https://tools.ietf.org/html/rfc6637#section-9).
class NEOPG_UNSTABLE_API EcdsaPublicKeyMaterial : public PublicKeyMaterial {
 public:
  ObjectIdentifier m_curve;
  MultiprecisionInteger m_key;

  static std::unique_ptr<EcdsaPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Ecdsa;
  };

  void write(std::ostream& out) const override;
};

/// Key material for [Ecdh public
/// keys](https://tools.ietf.org/html/rfc6637#section-9).
class NEOPG_UNSTABLE_API EcdhPublicKeyMaterial : public PublicKeyMaterial {
 public:
  ObjectIdentifier m_curve;
  MultiprecisionInteger m_key;
  uint8_t m_hash;
  uint8_t m_sym;

  static std::unique_ptr<EcdhPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Ecdh;
  };

  void write(std::ostream& out) const override;
};

/// Key material for [Eddsa public
/// keys](https://www.ietf.org/archive/id/draft-koch-eddsa-for-openpgp-04.txt).
class NEOPG_UNSTABLE_API EddsaPublicKeyMaterial : public PublicKeyMaterial {
 public:
  ObjectIdentifier m_curve;
  MultiprecisionInteger m_key;

  static std::unique_ptr<EddsaPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Eddsa;
  };

  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
