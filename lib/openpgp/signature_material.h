// OpenPGP signature material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/public_key_material.h>

#include <neopg/multiprecision_integer.h>
#include <neopg/parser_input.h>

#include <memory>

namespace NeoPG {

/// Algorithm-specific key material for a
/// [signature](https://tools.ietf.org/html/rfc4880#section-5.2).
class NEOPG_UNSTABLE_API SignatureMaterial {
 public:
  /// Create an instance based on the algorithm.
  /// @param algorithm algorithm specifier
  /// @param input parser input with key material
  /// Throws parse_error if input can not be parsed.
  static std::unique_ptr<SignatureMaterial> create_or_throw(
      PublicKeyAlgorithm algorithm, ParserInput& input);

  /// @return the algorithm specifier
  virtual PublicKeyAlgorithm algorithm() const = 0;

  /// Write the key material to the output stream.
  /// @param out output stream
  virtual void write(std::ostream& out) const = 0;
};

/// Key material for RSA public keys.
class NEOPG_UNSTABLE_API RsaSignatureMaterial : public SignatureMaterial {
 public:
  MultiprecisionInteger m_m_pow_d;  // m**d mod n

  static std::unique_ptr<RsaSignatureMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Rsa;
  };

  void write(std::ostream& out) const override;
};

/// Key material for DSA public keys.
class NEOPG_UNSTABLE_API DsaSignatureMaterial : public SignatureMaterial {
 public:
  MultiprecisionInteger m_r;
  MultiprecisionInteger m_s;

  static std::unique_ptr<DsaSignatureMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Dsa;
  };

  void write(std::ostream& out) const override;
};

/// Key material for ECDSA public keys.
class NEOPG_UNSTABLE_API EcdsaSignatureMaterial : public SignatureMaterial {
 public:
  MultiprecisionInteger m_r;
  MultiprecisionInteger m_s;

  static std::unique_ptr<EcdsaSignatureMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Ecdsa;
  };

  void write(std::ostream& out) const override;
};

/// Key material for EdDSA public keys.
class NEOPG_UNSTABLE_API EddsaSignatureMaterial : public SignatureMaterial {
 public:
  MultiprecisionInteger m_r;
  MultiprecisionInteger m_s;

  static std::unique_ptr<EddsaSignatureMaterial> create_or_throw(
      ParserInput& input);

  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Eddsa;
  };

  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
