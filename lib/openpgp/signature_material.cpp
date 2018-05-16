// OpenPGP signature material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_material.h>

#include <neopg/intern/cplusplus.h>

using namespace NeoPG;

std::unique_ptr<SignatureMaterial> SignatureMaterial::create_or_throw(
    PublicKeyAlgorithm algorithm, ParserInput& in) {
  switch (algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaSign:  // For example SKS 9BA6EDF38749875
      return RsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Dsa:
      return DsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Ecdsa:
      return EcdsaSignatureMaterial::create_or_throw(in);
    case PublicKeyAlgorithm::Eddsa:
      return EddsaSignatureMaterial::create_or_throw(in);
    default:
      in.error("unknown signature algorithm");
  }
  // Never reached.
  return nullptr;
}

std::unique_ptr<RsaSignatureMaterial> RsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<RsaSignatureMaterial>();
  data->m_m_pow_d.parse(in);
  return data;
}

void RsaSignatureMaterial::write(std::ostream& out) const {
  m_m_pow_d.write(out);
}

std::unique_ptr<DsaSignatureMaterial> DsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<DsaSignatureMaterial>();
  data->m_r.parse(in);
  data->m_s.parse(in);
  return data;
}

void DsaSignatureMaterial::write(std::ostream& out) const {
  m_r.write(out);
  m_s.write(out);
}

std::unique_ptr<EcdsaSignatureMaterial> EcdsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EcdsaSignatureMaterial>();
  data->m_r.parse(in);
  data->m_s.parse(in);
  return data;
}

void EcdsaSignatureMaterial::write(std::ostream& out) const {
  m_r.write(out);
  m_s.write(out);
}

std::unique_ptr<EddsaSignatureMaterial> EddsaSignatureMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EddsaSignatureMaterial>();
  data->m_r.parse(in);
  data->m_s.parse(in);
  return data;
}

void EddsaSignatureMaterial::write(std::ostream& out) const {
  m_r.write(out);
  m_s.write(out);
}
