// OpenPGP signature data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

#include <algorithm>
#include <iterator>

using namespace NeoPG;

namespace NeoPG {
namespace signature_data {
using namespace pegtl;

template <typename Rule>
struct action : nothing<Rule> {};

// This is for the subpacket parser.

// FIXME: Change subpacket type into unique_ptr and move it into the generated
// subpacket after parsing?

struct subpacket_data {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(
      Input& in, SignatureSubpacketLength& length, SignatureSubpacketType& type,
      bool& critical,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    if (in.size(length.m_length) >= length.m_length) {
      in.bump(length.m_length);
      return true;
    }
    return false;
  }
};

struct subpacket_length_one : uint8::range<0x00, 0xbf> {};
struct subpacket_length_two : seq<uint8::range<0xc0, 0xfe>, any> {};
struct subpacket_length_five : seq<uint8::one<0xff>, bytes<4>> {};

struct subpacket_length
    : sor<subpacket_length_one, subpacket_length_two, subpacket_length_five> {};
struct subpacket_type : any {};

struct subpacket : seq<subpacket_length, subpacket_type, subpacket_data> {};

struct subpacket_list : must<until<eof, subpacket>> {};

template <>
struct action<subpacket_length_one> {
  template <typename Input>
  static void apply(
      const Input& in, SignatureSubpacketLength& length,
      SignatureSubpacketType& type, bool& critical,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    auto val = (uint32_t)in.peek_byte(0);
    length.set_length(val - 1, SignatureSubpacketLengthType::OneOctet);
  }
};

template <>
struct action<subpacket_length_two> {
  template <typename Input>
  static void apply(
      const Input& in, SignatureSubpacketLength& length,
      SignatureSubpacketType& type, bool& critical,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val = ((val0 - 0xc0) << 8) + val1 + 192;
    length.set_length(val - 1, SignatureSubpacketLengthType::TwoOctet);
  }
};

template <>
struct action<subpacket_length_five> {
  template <typename Input>
  static void apply(
      const Input& in, SignatureSubpacketLength& length,
      SignatureSubpacketType& type, bool& critical,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    auto val0 = (uint32_t)in.peek_byte(1);
    auto val1 = (uint32_t)in.peek_byte(2);
    auto val2 = (uint32_t)in.peek_byte(3);
    auto val3 = (uint32_t)in.peek_byte(4);
    auto val = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
    length.set_length(val - 1, SignatureSubpacketLengthType::FiveOctet);
  }
};

template <>
struct action<subpacket_type> {
  template <typename Input>
  static void apply(
      const Input& in, SignatureSubpacketLength& length,
      SignatureSubpacketType& type, bool& critical,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    auto val = (uint32_t)in.peek_byte(0);
    critical = (val & 0x80) ? true : false;
    type = static_cast<SignatureSubpacketType>(val & 0x7f);
  }
};

template <>
struct action<subpacket_data> {
  template <typename Input>
  static void apply(
      const Input& in, SignatureSubpacketLength& length,
      SignatureSubpacketType& type, bool& critical,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    ParserInput in2(in.begin(), in.size());
    auto subpacket = SignatureSubpacket::create_or_throw(type, in2);
    subpacket->m_critical = critical;
    subpackets.push_back(std::move(subpacket));
    // FIXME: In case of error, rewrite exception to point to byte offset.
  }
};

// End of subpacket parser.

struct v3_hashed : must<one<0x05>> {};

struct type : must<any> {};

struct created : must<bytes<4>> {};

struct signer : must<bytes<8>> {};

struct quick : must<bytes<2>> {};

struct public_key_algorithm : must<any> {};

struct hash_algorithm : must<any> {};

// A custom rule to match subpacket data.  This is stateful, because it requires
// the preceeding length information, and matches exactly subpackets_length
// bytes.
struct subpackets_data {
  using analyze_t = analysis::generic<analysis::rule_type::ANY>;
  template <apply_mode A, rewind_mode M, template <typename...> class Action,
            template <typename...> class Control, typename Input>
  static bool match(
      Input& in, uint16_t& subpackets_length,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    if (in.size(subpackets_length) >= subpackets_length) {
      in.bump(subpackets_length);
      return true;
    }
    return false;
  }
};

struct subpackets_length : bytes<2> {};
struct subpackets : must<subpackets_length, subpackets_data> {};

template <>
struct action<type> {
  template <typename Input>
  static void apply(const Input& in, SignatureType& type) {
    type = static_cast<SignatureType>(in.peek_byte());
  }
};

template <>
struct action<created> {
  template <typename Input>
  static void apply(const Input& in, uint32_t& created) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    auto val2 = (uint32_t)in.peek_byte(2);
    auto val3 = (uint32_t)in.peek_byte(3);
    created = (val0 << 24) + (val1 << 16) + (val2 << 8) + val3;
  }
};

template <>
struct action<signer> {
  template <typename Input>
  static void apply(const Input& in, std::array<uint8_t, 8>& signer) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    std::copy_n(begin, in.size(), std::begin(signer));
  }
};

template <>
struct action<public_key_algorithm> {
  template <typename Input>
  static void apply(const Input& in, PublicKeyAlgorithm& algorithm) {
    algorithm = static_cast<PublicKeyAlgorithm>(in.peek_byte());
  }
};

template <>
struct action<hash_algorithm> {
  template <typename Input>
  static void apply(const Input& in, HashAlgorithm& algorithm) {
    algorithm = static_cast<HashAlgorithm>(in.peek_byte());
  }
};

template <>
struct action<quick> {
  template <typename Input>
  static void apply(const Input& in, std::array<uint8_t, 2>& quick) {
    auto begin = reinterpret_cast<const uint8_t*>(in.begin());
    std::copy_n(begin, in.size(), std::begin(quick));
  }
};

template <>
struct action<subpackets_length> {
  template <typename Input>
  static void apply(
      const Input& in, uint16_t& length,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    auto val0 = (uint32_t)in.peek_byte(0);
    auto val1 = (uint32_t)in.peek_byte(1);
    length = (val0 << 8) + val1;
  }
};

template <>
struct action<subpackets_data> {
  template <typename Input>
  static void apply(
      const Input& in, uint16_t& length,
      std::vector<std::unique_ptr<SignatureSubpacket>>& subpackets) {
    ParserInput in2(in.begin(), in.size());
    SignatureSubpacketLength subpacket_length(0);
    SignatureSubpacketType type;
    bool critical;
    pegtl::parse<signature_data::subpacket_list, signature_data::action>(
        in2.m_impl->m_input, subpacket_length, type, critical, subpackets);
    // FIXME: In case of error, rewrite exception to point to byte offset.
  }
};

}  // namespace signature_data
}  // namespace NeoPG

std::unique_ptr<SignatureData> SignatureData::create_or_throw(
    SignatureVersion version, ParserInput& in) {
  std::unique_ptr<SignatureData> signature;
  switch (version) {
    case SignatureVersion::V2:
    case SignatureVersion::V3:
      signature = V2o3SignatureData::create_or_throw(version, in);
      break;
    case SignatureVersion::V4:
      signature = V4SignatureData::create_or_throw(in);
      break;
    default:
      in.error("unknown signature version");
  }
  // if (in.size() != 0) in.error("trailing data in signature");

  return signature;
}

std::unique_ptr<V2o3SignatureData> V2o3SignatureData::create_or_throw(
    SignatureVersion version, ParserInput& in) {
  auto packet = make_unique<V2o3SignatureData>();
  packet->m_version = version;
  // Not very elegant, but makes it easier to reuse the same actions.
  pegtl::parse<signature_data::v3_hashed, signature_data::action>(
      in.m_impl->m_input);
  pegtl::parse<signature_data::type, signature_data::action>(in.m_impl->m_input,
                                                             packet->m_type);
  pegtl::parse<signature_data::created, signature_data::action>(
      in.m_impl->m_input, packet->m_created);
  pegtl::parse<signature_data::signer, signature_data::action>(
      in.m_impl->m_input, packet->m_signer);
  pegtl::parse<signature_data::public_key_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_public_key_algorithm);
  pegtl::parse<signature_data::hash_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_hash_algorithm);
  pegtl::parse<signature_data::quick, signature_data::action>(
      in.m_impl->m_input, packet->m_quick);

  packet->m_signature =
      SignatureMaterial::create_or_throw(packet->m_public_key_algorithm, in);
#if 0
  switch (packet->m_public_key_algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaEncrypt:
    case PublicKeyAlgorithm::RsaSign:
      break;
    default:
      in.error("unknown v3 signature algorithm");
  }
#endif

  return packet;
}

void V2o3SignatureData::write(std::ostream& out) const {
  out << static_cast<uint8_t>(0x05);
  out << static_cast<uint8_t>(m_type);
  out << static_cast<uint8_t>(m_created >> 24)
      << static_cast<uint8_t>(m_created >> 16)
      << static_cast<uint8_t>(m_created >> 8)
      << static_cast<uint8_t>(m_created);
  out.write(reinterpret_cast<const char*>(m_signer.data()), m_signer.size());
  out << static_cast<uint8_t>(m_public_key_algorithm);
  out << static_cast<uint8_t>(m_hash_algorithm);
  out.write(reinterpret_cast<const char*>(m_quick.data()), m_quick.size());
  // FIXME: Really optional?  (Useful for testing)
  if (m_signature) m_signature->write(out);
}

std::unique_ptr<V4SignatureData> V4SignatureData::create_or_throw(
    ParserInput& in) {
  auto packet = make_unique<V4SignatureData>();

  pegtl::parse<signature_data::type, signature_data::action>(in.m_impl->m_input,
                                                             packet->m_type);
  pegtl::parse<signature_data::public_key_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_public_key_algorithm);
  pegtl::parse<signature_data::hash_algorithm, signature_data::action>(
      in.m_impl->m_input, packet->m_hash_algorithm);

  uint16_t length;
  pegtl::parse<signature_data::subpackets, signature_data::action>(
      in.m_impl->m_input, length, packet->m_hashed_subpackets);
  pegtl::parse<signature_data::subpackets, signature_data::action>(
      in.m_impl->m_input, length, packet->m_unhashed_subpackets);

  pegtl::parse<signature_data::quick, signature_data::action>(
      in.m_impl->m_input, packet->m_quick);

  packet->m_signature =
      SignatureMaterial::create_or_throw(packet->m_public_key_algorithm, in);
#if 0
  switch (packet->m_public_key_algorithm) {
    case PublicKeyAlgorithm::Rsa:
    case PublicKeyAlgorithm::RsaEncrypt:
    case PublicKeyAlgorithm::RsaSign:
      break;
    default:
      in.error("unknown v4 signature algorithm");
  }
#endif

  return packet;
}

void V4SignatureData::write(std::ostream& out) const {
  // FIXME?
  out << static_cast<uint8_t>(m_type);
  out << static_cast<uint8_t>(m_public_key_algorithm);
  out << static_cast<uint8_t>(m_hash_algorithm);
  // FIXME: Subpackets
  out.write(reinterpret_cast<const char*>(m_quick.data()), m_quick.size());
  // FIXME: Really optional?  (Useful for testing)
  if (m_signature) m_signature->write(out);
}
