// OpenPGP signature subpacket (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_subpacket.h>

#include <neopg/parser_input.h>
#include <neopg/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace signature_subpacket {
using namespace pegtl;

struct uint32_field : bytes<4> {};

struct uint8_field : any {};

struct string_field : star<any> {};

struct created : must<uint32_field> {};
struct sig_expires : must<uint32_field> {};
struct key_expires : must<uint32_field> {};
struct exportable : must<uint8_field> {};
struct trust_signature : must<any, any> {};
struct regular_expression : must<string_field> {};
struct primary : must<uint8_field> {};
struct flags : must<uint8_field> {};
struct features : star<uint8_field> {};
struct pref_symmetric_algos : star<uint8_field> {};
struct pref_hash_algos : star<uint8_field> {};
struct pref_compression_algos : star<uint8_field> {};
struct keyserver_pref : star<uint8_field> {};
struct issuer : must<rep<8, uint8_field>> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<trust_signature> {
  template <typename Input>
  static void apply(const Input& in, uint8_t& level, uint8_t& amount) {
    level = static_cast<uint8_t>(in.peek_byte(0));
    amount = static_cast<uint8_t>(in.peek_byte(1));
  }
};

template <>
struct action<uint8_field> {
  template <typename Input>
  static void apply(const Input& in, uint8_t& field) {
    field = static_cast<uint8_t>(in.peek_byte());
  }

  template <typename Input>
  static void apply(const Input& in, std::vector<uint8_t>& vec) {
    auto val = static_cast<uint8_t>(in.peek_byte());
    vec.emplace_back(val);
  }
};

template <>
struct action<uint32_field> {
  template <typename Input>
  static void apply(const Input& in, uint32_t& field) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val2 = (uint32_t)in.peek_byte(2);
    auto val3 = (uint32_t)in.peek_byte(3);
    field = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
  }
};

template <>
struct action<string_field> {
  template <typename Input>
  static void apply(const Input& in, std::string& field) {
    field = in.string();
  }
};

}  // namespace signature_subpacket
}  // namespace NeoPG

void SignatureSubpacketLength::verify_length(
    uint32_t length, SignatureSubpacketLengthType length_type) {
  if (length_type == SignatureSubpacketLengthType::OneOctet and
      not(length <= 0xbf)) {
    throw std::logic_error("Invalid packet length for one octet");
  } else if (length_type == SignatureSubpacketLengthType::TwoOctet and
             not(length >= 0xc0 and length <= 0x3fbf)) {
    throw std::logic_error("Invalid packet length for two octets");
  }
}

SignatureSubpacketLengthType SignatureSubpacketLength::best_length_type(
    uint32_t length) {
  if (length <= 0xbf)
    return SignatureSubpacketLengthType::OneOctet;
  else if (length <= 0x3fbf)
    return SignatureSubpacketLengthType::TwoOctet;
  else
    return SignatureSubpacketLengthType::FiveOctet;
}

void SignatureSubpacketLength::set_length(
    uint32_t length, SignatureSubpacketLengthType length_type) {
  verify_length(length, length_type);
  m_length_type = length_type;
  m_length = length;
}

SignatureSubpacketLength::SignatureSubpacketLength(
    uint32_t length, SignatureSubpacketLengthType length_type) {
  set_length(length, length_type);
}

void SignatureSubpacketLength::write(std::ostream& out) {
  SignatureSubpacketLengthType lentype = m_length_type;
  if (lentype == SignatureSubpacketLengthType::Default)
    lentype = best_length_type(m_length);

  switch (lentype) {
    case SignatureSubpacketLengthType::OneOctet:
      out << (uint8_t)m_length;
      break;

    case SignatureSubpacketLengthType::TwoOctet: {
      uint32_t adj_length = m_length - 0xc0;
      out << (uint8_t)(((adj_length >> 8) & 0x3f) + 0xc0)
          << ((uint8_t)(adj_length & 0xff));
    } break;

    case SignatureSubpacketLengthType::FiveOctet:
      out << (uint8_t)0xff << ((uint8_t)((m_length >> 24) & 0xff))
          << ((uint8_t)((m_length >> 16) & 0xff))
          << ((uint8_t)((m_length >> 8) & 0xff))
          << ((uint8_t)(m_length & 0xff));
      break;

    // LCOV_EXCL_START
    case SignatureSubpacketLengthType::Default:
      throw std::logic_error(
          "Unspecific subpacket length type (shouldn't happen).");
      // LCOV_EXCL_STOP
  }
}

std::unique_ptr<SignatureSubpacket> SignatureSubpacket::create_or_throw(
    SignatureSubpacketType type, ParserInput& in) {
  switch (type) {
    case SignatureSubpacketType::SignatureCreationTime:
      return SignatureCreationTimeSubpacket::create_or_throw(in);
    case SignatureSubpacketType::SignatureExpirationTime:
      return SignatureExpirationTimeSubpacket::create_or_throw(in);
    case SignatureSubpacketType::ExportableCertification:
      return ExportableCertificationSubpacket::create_or_throw(in);
    case SignatureSubpacketType::TrustSignature:
      return TrustSignatureSubpacket::create_or_throw(in);
    case SignatureSubpacketType::RegularExpression:
      return RegularExpressionSubpacket::create_or_throw(in);
    case SignatureSubpacketType::KeyExpirationTime:
      return KeyExpirationTimeSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PreferredSymmetricAlgorithms:
      return PreferredSymmetricAlgorithmsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::Issuer:
      return IssuerSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PreferredHashAlgorithms:
      return PreferredHashAlgorithmsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PreferredCompressionAlgorithms:
      return PreferredCompressionAlgorithmsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::KeyServerPreferences:
      return KeyServerPreferencesSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PrimaryUserId:
      return PrimaryUserIdSubpacket::create_or_throw(in);
    case SignatureSubpacketType::KeyFlags:
      return KeyFlagsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::Features:
      return FeaturesSubpacket::create_or_throw(in);
    default:
      return NeoPG::make_unique<RawSignatureSubpacket>(
          type, std::string(in.current(), in.size()));
  }
  // if (in.size() != 0) in.error("trailing data in signature subpacket");
}

uint32_t SignatureSubpacket::body_length() const {
  CountingStream cnt;
  write_body(cnt);
  return cnt.bytes_written();
}

void SignatureSubpacket::write(std::ostream& out) const {
  if (m_length) {
    m_length->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    // Length includes the type octet.
    if (len == (uint32_t)-1)
      ;  // FIXME;
    len = len + 1;
    SignatureSubpacketLength default_length(len);
    default_length.write(out);
  }
  out << static_cast<uint8_t>(type());
  write_body(out);
}

// Subpacket type 2
void SignatureCreationTimeSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
}

std::unique_ptr<SignatureCreationTimeSubpacket>
SignatureCreationTimeSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<SignatureCreationTimeSubpacket>();

  pegtl::parse<signature_subpacket::created, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_created);

  return subpacket;
}

// Subpacket type 3
void SignatureExpirationTimeSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_expiration >> 24)
      << static_cast<uint8_t>(m_expiration >> 16)
      << static_cast<uint8_t>(m_expiration >> 8)
      << static_cast<uint8_t>(m_expiration);
}

std::unique_ptr<SignatureExpirationTimeSubpacket>
SignatureExpirationTimeSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<SignatureExpirationTimeSubpacket>();

  pegtl::parse<signature_subpacket::sig_expires, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_expiration);

  return subpacket;
}

// Subpacket type 4
void ExportableCertificationSubpacket::write_body(std::ostream& out) const {
  out << m_exportable;
}

std::unique_ptr<ExportableCertificationSubpacket>
ExportableCertificationSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<ExportableCertificationSubpacket>();

  pegtl::parse<signature_subpacket::exportable, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_exportable);

  return subpacket;
}

// Subpacket type 5
void TrustSignatureSubpacket::write_body(std::ostream& out) const {
  out << m_level << m_amount;
}

std::unique_ptr<TrustSignatureSubpacket>
TrustSignatureSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<TrustSignatureSubpacket>();

  pegtl::parse<signature_subpacket::trust_signature,
               signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_level, subpacket->m_amount);

  return subpacket;
}

// Subpacket type 6
void RegularExpressionSubpacket::write_body(std::ostream& out) const {
  out << m_regex;
}

std::unique_ptr<RegularExpressionSubpacket>
RegularExpressionSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<RegularExpressionSubpacket>();

  pegtl::parse<signature_subpacket::regular_expression,
               signature_subpacket::action>(in.m_impl->m_input,
                                            subpacket->m_regex);

  return subpacket;
}

// Subpacket type 9
void KeyExpirationTimeSubpacket::write_body(std::ostream& out) const {
  out << static_cast<uint8_t>(m_expiration >> 24)
      << static_cast<uint8_t>(m_expiration >> 16)
      << static_cast<uint8_t>(m_expiration >> 8)
      << static_cast<uint8_t>(m_expiration);
}

std::unique_ptr<KeyExpirationTimeSubpacket>
KeyExpirationTimeSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<KeyExpirationTimeSubpacket>();

  pegtl::parse<signature_subpacket::key_expires, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_expiration);

  return subpacket;
}

void PreferredSymmetricAlgorithmsSubpacket::write_body(
    std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_algorithms.data()),
            m_algorithms.size());
}

std::unique_ptr<PreferredSymmetricAlgorithmsSubpacket>
PreferredSymmetricAlgorithmsSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<PreferredSymmetricAlgorithmsSubpacket>();

  pegtl::parse<signature_subpacket::pref_symmetric_algos,
               signature_subpacket::action>(in.m_impl->m_input,
                                            subpacket->m_algorithms);

  return subpacket;
}

void IssuerSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_issuer.data()), m_issuer.size());
}

std::unique_ptr<IssuerSubpacket> IssuerSubpacket::create_or_throw(
    ParserInput& in) {
  auto subpacket = make_unique<IssuerSubpacket>();

  pegtl::parse<signature_subpacket::issuer, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_issuer);

  return subpacket;
}

void PreferredHashAlgorithmsSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_algorithms.data()),
            m_algorithms.size());
}

std::unique_ptr<PreferredHashAlgorithmsSubpacket>
PreferredHashAlgorithmsSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<PreferredHashAlgorithmsSubpacket>();

  pegtl::parse<signature_subpacket::pref_hash_algos,
               signature_subpacket::action>(in.m_impl->m_input,
                                            subpacket->m_algorithms);

  return subpacket;
}

void PreferredCompressionAlgorithmsSubpacket::write_body(
    std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_algorithms.data()),
            m_algorithms.size());
}

std::unique_ptr<PreferredCompressionAlgorithmsSubpacket>
PreferredCompressionAlgorithmsSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<PreferredCompressionAlgorithmsSubpacket>();

  pegtl::parse<signature_subpacket::pref_compression_algos,
               signature_subpacket::action>(in.m_impl->m_input,
                                            subpacket->m_algorithms);

  return subpacket;
}

void KeyServerPreferencesSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_features.data()),
            m_features.size());
}

std::unique_ptr<KeyServerPreferencesSubpacket>
KeyServerPreferencesSubpacket::create_or_throw(ParserInput& in) {
  auto subpacket = make_unique<KeyServerPreferencesSubpacket>();

  pegtl::parse<signature_subpacket::keyserver_pref,
               signature_subpacket::action>(in.m_impl->m_input,
                                            subpacket->m_features);

  return subpacket;
}

void PrimaryUserIdSubpacket::write_body(std::ostream& out) const {
  out << m_primary;
}

std::unique_ptr<PrimaryUserIdSubpacket> PrimaryUserIdSubpacket::create_or_throw(
    ParserInput& in) {
  auto subpacket = make_unique<PrimaryUserIdSubpacket>();

  pegtl::parse<signature_subpacket::primary, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_primary);

  return subpacket;
}

void KeyFlagsSubpacket::write_body(std::ostream& out) const { out << m_flags; }

std::unique_ptr<KeyFlagsSubpacket> KeyFlagsSubpacket::create_or_throw(
    ParserInput& in) {
  auto subpacket = make_unique<KeyFlagsSubpacket>();

  pegtl::parse<signature_subpacket::flags, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_flags);

  return subpacket;
}

void FeaturesSubpacket::write_body(std::ostream& out) const {
  out.write(reinterpret_cast<const char*>(m_features.data()),
            m_features.size());
}

std::unique_ptr<FeaturesSubpacket> FeaturesSubpacket::create_or_throw(
    ParserInput& in) {
  auto subpacket = make_unique<FeaturesSubpacket>();

  pegtl::parse<signature_subpacket::features, signature_subpacket::action>(
      in.m_impl->m_input, subpacket->m_features);

  return subpacket;
}
