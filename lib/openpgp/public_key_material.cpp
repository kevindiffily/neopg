// OpenPGP public key material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace public_key_material {
using namespace pegtl;

struct ecdh_kdf : must<one<(char)0x03>, one<(char)0x01>, any, any> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<ecdh_kdf> {
  template <typename Input>
  static void apply(const Input& in, uint8_t m_hash, uint8_t m_sym) {
    m_hash = in.peek_byte(2);
    m_sym = in.peek_byte(3);
  }
};

}  // namespace public_key_material
}  // namespace NeoPG

using namespace NeoPG;

std::unique_ptr<PublicKeyMaterial> PublicKeyMaterial::create_or_throw(
    PublicKeyAlgorithm algorithm, ParserInput& in) {
  switch (algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaEncrypt:
    case PublicKeyAlgorithm::RsaSign:
      return RsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Dsa:
      return DsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Elgamal:
    case PublicKeyAlgorithm::ElgamalEncrypt:
      return ElgamalPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Ecdsa:
      return EcdsaPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Ecdh:
      return EcdhPublicKeyMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Eddsa:
      return EddsaPublicKeyMaterial::create_or_throw(in);
    default:
      in.error("unknown public key algorithm");
  }
  // Never reached.
  return nullptr;
}

std::unique_ptr<RsaPublicKeyMaterial> RsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<RsaPublicKeyMaterial>();
  data->m_n.parse(in);
  data->m_e.parse(in);
  return data;
}

void RsaPublicKeyMaterial::write(std::ostream& out) const {
  m_n.write(out);
  m_e.write(out);
}

std::unique_ptr<DsaPublicKeyMaterial> DsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<DsaPublicKeyMaterial>();
  data->m_p.parse(in);
  data->m_q.parse(in);
  data->m_g.parse(in);
  data->m_y.parse(in);
  return data;
}

void DsaPublicKeyMaterial::write(std::ostream& out) const {
  m_p.write(out);
  m_q.write(out);
  m_g.write(out);
  m_y.write(out);
}

std::unique_ptr<ElgamalPublicKeyMaterial>
ElgamalPublicKeyMaterial::create_or_throw(ParserInput& in) {
  auto data = make_unique<ElgamalPublicKeyMaterial>();
  data->m_p.parse(in);
  data->m_g.parse(in);
  data->m_y.parse(in);
  return data;
}

void ElgamalPublicKeyMaterial::write(std::ostream& out) const {
  m_p.write(out);
  m_g.write(out);
  m_y.write(out);
}

std::unique_ptr<EcdsaPublicKeyMaterial> EcdsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EcdsaPublicKeyMaterial>();
  data->m_curve.parse(in);
  data->m_key.parse(in);

  return data;
}

void EcdsaPublicKeyMaterial::write(std::ostream& out) const {
  m_curve.write(out);
  m_key.write(out);
}

std::unique_ptr<EcdhPublicKeyMaterial> EcdhPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EcdhPublicKeyMaterial>();
  data->m_curve.parse(in);
  data->m_key.parse(in);
  pegtl::parse<public_key_material::ecdh_kdf, public_key_material::action>(
      in.m_impl->m_input, data->m_hash, data->m_sym);
  return data;
}

void EcdhPublicKeyMaterial::write(std::ostream& out) const {
  m_curve.write(out);
  m_key.write(out);
  out << static_cast<uint8_t>(0x03) << static_cast<uint8_t>(0x01)
      << static_cast<uint8_t>(m_hash) << static_cast<uint8_t>(m_sym);
}

std::unique_ptr<EddsaPublicKeyMaterial> EddsaPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EddsaPublicKeyMaterial>();
  data->m_curve.parse(in);
  data->m_key.parse(in);
  return data;
}

void EddsaPublicKeyMaterial::write(std::ostream& out) const {
  m_curve.write(out);
  m_key.write(out);
}
