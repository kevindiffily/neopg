/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg-tool/command.h>
#include <neopg-tool/packet_command.h>

#include <neopg/marker_packet.h>
#include <neopg/openpgp.h>
#include <neopg/parser_error.h>
#include <neopg/public_key_packet.h>
#include <neopg/public_subkey_packet.h>
#include <neopg/raw_packet.h>
#include <neopg/signature_packet.h>
#include <neopg/stream.h>
#include <neopg/user_id_packet.h>
#include <neopg/v3_public_key_data.h>
#include <neopg/v4_public_key_data.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>
#include <botan/hex.h>

#include <botan/ber_dec.h>
#include <botan/oids.h>

#include <CLI11.hpp>

#include <spdlog/fmt/fmt.h>

#include <rang.hpp>

#include <tao/json.hpp>

#include <spdlog/fmt/fmt.h>

#include <rang.hpp>

#include <iostream>

namespace NeoPG {

void MarkerPacketCommand::run() {
  MarkerPacket packet;
  packet.write(std::cout);
}

void UserIdPacketCommand::run() {
  UserIdPacket packet;
  packet.m_content = m_uid;
  packet.write(std::cout);
}

static void output_public_key_data(PublicKeyData* pub) {
  PublicKeyMaterial* key = nullptr;
  switch (pub->version()) {
    case PublicKeyVersion::V2:
    case PublicKeyVersion::V3: {
      auto v3pub = dynamic_cast<V3PublicKeyData*>(pub);
      std::cout << "\tversion " << static_cast<int>(pub->version()) << ", algo "
                << static_cast<int>(v3pub->m_algorithm) << ", created "
                << v3pub->m_created << ", expires " << v3pub->m_days_valid
                << "\n";
      key = v3pub->m_key.get();
    } break;
    case PublicKeyVersion::V4: {
      auto v4pub = dynamic_cast<V4PublicKeyData*>(pub);
      std::cout << "\tversion " << static_cast<int>(pub->version()) << ", algo "
                << static_cast<int>(v4pub->m_algorithm) << ", created "
                << v4pub->m_created << ", expires 0"
                << "\n";
      key = v4pub->m_key.get();
    } break;
    default:
      std::cout << "\tversion " << static_cast<int>(pub->version()) << "\n";
      break;
  }
  if (key) {
    switch (key->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(key);
        std::cout << "\tpkey[0]: [" << rsa->m_n.length() << " bits]\n";
        std::cout << "\tpkey[1]: [" << rsa->m_e.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<DsaPublicKeyMaterial*>(key);
        std::cout << "\tpkey[0]: [" << dsa->m_p.length() << " bits]\n";
        std::cout << "\tpkey[1]: [" << dsa->m_q.length() << " bits]\n";
        std::cout << "\tpkey[2]: [" << dsa->m_g.length() << " bits]\n";
        std::cout << "\tpkey[3]: [" << dsa->m_y.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Elgamal: {
        auto elgamal = dynamic_cast<ElgamalPublicKeyMaterial*>(key);
        std::cout << "\tpkey[0]: [" << elgamal->m_p.length() << " bits]\n";
        std::cout << "\tpkey[1]: [" << elgamal->m_g.length() << " bits]\n";
        std::cout << "\tpkey[2]: [" << elgamal->m_y.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<EcdsaPublicKeyMaterial*>(key);
        const std::string oidstr = ecdsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        std::cout << "\tpkey[0]: [" << (1 + ecdsa->m_curve.length()) * 8
                  << " bits] " << Botan::OIDS::lookup(oid) << " (" << oidstr
                  << ")\n";
        std::cout << "\tpkey[1]: [" << ecdsa->m_key.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<EddsaPublicKeyMaterial*>(key);
        const std::string oidstr = eddsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        std::cout << "\tpkey[0]: [" << (1 + eddsa->m_curve.length()) * 8
                  << " bits] " << Botan::OIDS::lookup(oid) << " (" << oidstr
                  << ")\n";
        std::cout << "\tpkey[1]: [" << eddsa->m_key.length() << " bits]\n";
      } break;
      default:
        break;
    }
    auto keyid = pub->keyid();
    std::cout << "\tkeyid: " << Botan::hex_encode(keyid.data(), keyid.size())
              << "\n";
  }
}

static void output_signature_subpacket(const std::string& variant,
                                       SignatureSubpacket* subpacket) {
  std::cout << "\t" << (subpacket->m_critical ? "critical " : "") << variant
            << " " << static_cast<int>(subpacket->type()) << " len "
            << subpacket->body_length();
  switch (subpacket->type()) {
    case SignatureSubpacketType::SignatureCreationTime: {
      auto sub = dynamic_cast<SignatureCreationTimeSubpacket*>(subpacket);
      std::cout << " (sig created " << sub->m_created << ")";
      break;
    }
    case SignatureSubpacketType::SignatureExpirationTime: {
      auto sub = dynamic_cast<SignatureExpirationTimeSubpacket*>(subpacket);
      if (sub->m_expiration)
        std::cout << " (sig expires after " << sub->m_expiration << ")";
      else
        std::cout << " (sig does not expire)";
      break;
    }
    case SignatureSubpacketType::ExportableCertification: {
      auto sub = dynamic_cast<ExportableCertificationSubpacket*>(subpacket);
      if (sub->m_exportable)
        std::cout << " (exportable)";
      else
        std::cout << " (not exportable)";
      break;
    }
    case SignatureSubpacketType::TrustSignature: {
      auto sub = dynamic_cast<TrustSignatureSubpacket*>(subpacket);
      std::cout << " (trust signature of depth " << (int)sub->m_level
                << ", value " << (int)sub->m_amount << ")";
      break;
    }
    case SignatureSubpacketType::RegularExpression: {
      auto sub = dynamic_cast<RegularExpressionSubpacket*>(subpacket);
      const tao::json::value str = sub->m_regex;
      std::cout << " (regular expression: " << str << ")";
      break;
    }
    case SignatureSubpacketType::KeyExpirationTime: {
      auto sub = dynamic_cast<KeyExpirationTimeSubpacket*>(subpacket);
      if (sub->m_expiration) {
        int seconds = sub->m_expiration;
        int minutes = seconds / 60;
        int hours = minutes / 60;
        int days = hours / 24;
        int years = days / 365;
        std::cout << " (key expires after " << years << "y" << (days % 365)
                  << "d" << (hours % 24) << "h" << (minutes % 60) << "m)";
      } else
        std::cout << " (key does not expire)";
      break;
    }
    case SignatureSubpacketType::PreferredSymmetricAlgorithms: {
      auto sub =
          dynamic_cast<PreferredSymmetricAlgorithmsSubpacket*>(subpacket);
      std::cout << " (pref-sym-algos:";
      for (auto& algorithm : sub->m_algorithms)
        std::cout << " " << (int)algorithm;
      std::cout << ")";
      break;
    }
    case SignatureSubpacketType::Issuer: {
      auto sub = dynamic_cast<IssuerSubpacket*>(subpacket);
      std::cout << " (issuer key ID "
                << Botan::hex_encode(sub->m_issuer.data(), sub->m_issuer.size())
                << ")";
      break;
    }
    case SignatureSubpacketType::PreferredHashAlgorithms: {
      auto sub = dynamic_cast<PreferredHashAlgorithmsSubpacket*>(subpacket);
      std::cout << " (pref-hash-algos:";
      for (auto& algorithm : sub->m_algorithms)
        std::cout << " " << (int)algorithm;
      std::cout << ")";
      break;
    }
    case SignatureSubpacketType::PreferredCompressionAlgorithms: {
      auto sub =
          dynamic_cast<PreferredCompressionAlgorithmsSubpacket*>(subpacket);
      std::cout << " (pref-zip-algos:";
      for (auto& algorithm : sub->m_algorithms)
        std::cout << " " << (int)algorithm;
      std::cout << ")";
      break;
    }
    case SignatureSubpacketType::KeyServerPreferences: {
      auto sub = dynamic_cast<KeyServerPreferencesSubpacket*>(subpacket);
      std::cout << " (keyserver preferences: "
                << Botan::hex_encode(sub->m_features.data(),
                                     sub->m_features.size())
                << ")";
      break;
    }
    case SignatureSubpacketType::PrimaryUserId: {
      auto sub = dynamic_cast<PrimaryUserIdSubpacket*>(subpacket);
      std::cout << " (primary user ID: "
                << fmt::format("{:02x}", static_cast<int>(sub->m_primary))
                << ")";
      break;
    }
    case SignatureSubpacketType::KeyFlags: {
      auto sub = dynamic_cast<KeyFlagsSubpacket*>(subpacket);
      std::cout << " (key flags: " << Botan::hex_encode(&sub->m_flags, 1)
                << ")";
      break;
    }
    case SignatureSubpacketType::Features: {
      auto sub = dynamic_cast<FeaturesSubpacket*>(subpacket);
      std::cout << " (features: "
                << Botan::hex_encode(sub->m_features.data(),
                                     sub->m_features.size())
                << ")";
      break;
    }
    default:
      break;
  }
  std::cout << "\n";
}

static void output_signature_data(SignatureData* sig) {
  SignatureMaterial* sigmat = nullptr;
  switch (sig->version()) {
    case SignatureVersion::V2:
    case SignatureVersion::V3: {
      auto v3sig = dynamic_cast<V2o3SignatureData*>(sig);
      std::cout << "\tversion 3, created " << v3sig->m_created
                << ", md5len 5, sigclass 0x"
                << fmt::format("{:02x}",
                               static_cast<int>(v3sig->signature_type()))
                << "\n";
      std::cout << "\tdigest algo " << static_cast<int>(v3sig->hash_algorithm())
                << ", begin of digest "
                << fmt::format("{:02x}",
                               static_cast<int>(v3sig->m_quick.data()[0]))
                << " "
                << fmt::format("{:02x}",
                               static_cast<int>(v3sig->m_quick.data()[1]))
                << "\n";
      sigmat = v3sig->m_signature.get();
    } break;
    case SignatureVersion::V4: {
      auto v4sig = dynamic_cast<V4SignatureData*>(sig);
      // FIXME: Try to get created from subpackets.
      std::cout << "\tversion 4, created " << v4sig->m_created
                << ", md5len 0, sigclass 0x"
                << fmt::format("{:02x}",
                               static_cast<int>(v4sig->signature_type()))
                << "\n";
      std::cout << "\tdigest algo " << static_cast<int>(v4sig->hash_algorithm())
                << ", begin of digest "
                << fmt::format("{:02x}",
                               static_cast<int>(v4sig->m_quick.data()[0]))
                << " "
                << fmt::format("{:02x}",
                               static_cast<int>(v4sig->m_quick.data()[1]))
                << "\n";
      for (auto& subpacket : v4sig->m_hashed_subpackets) {
        output_signature_subpacket("hashed subpkt", subpacket.get());
      }
      for (auto& subpacket : v4sig->m_unhashed_subpackets) {
        output_signature_subpacket("subpkt", subpacket.get());
      }
      sigmat = v4sig->m_signature.get();
    } break;
    default:
      break;
  }
  if (sigmat) {
    switch (sigmat->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<RsaSignatureMaterial*>(sigmat);
        std::cout << "\tdata: [" << rsa->m_m_pow_d.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<DsaSignatureMaterial*>(sigmat);
        std::cout << "\tdata: [" << dsa->m_r.length() << " bits]\n";
        std::cout << "\tdata: [" << dsa->m_s.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<EcdsaSignatureMaterial*>(sigmat);
        std::cout << "\tdata: [" << ecdsa->m_r.length() << " bits]\n";
        std::cout << "\tdata: [" << ecdsa->m_s.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<EddsaSignatureMaterial*>(sigmat);
        std::cout << "\tdata: [" << eddsa->m_r.length() << " bits]\n";
        std::cout << "\tdata: [" << eddsa->m_s.length() << " bits]\n";
      } break;
      default:
        break;
    }
  }
}

struct LegacyPacketSink : public RawPacketSink {
  void next_packet(std::unique_ptr<PacketHeader> header, const char* data,
                   size_t length) {
    // # off=0 ctb=99 tag=6 hlen=3 plen=525
    // # off=229725 ctb=d1 tag=17 hlen=6 plen=3033 new-ctb

    // FIXME: Use fmt library instead of boost, expand PacketHeader API.
    std::stringstream head_ss;
    header->write(head_ss);
    auto head = head_ss.str();

    auto new_header = dynamic_cast<NewPacketHeader*>(header.get());

    std::cout << rang::fg::gray << "# off=" << header->m_offset << " ctb="
              << fmt::format("{:02x}", static_cast<int>((uint8_t)head[0]))
              << " tag=" << (int)header->type() << " hlen=" << head.length()
              << " plen=" << length << (new_header ? " new-ctb" : "")
              << rang::style::reset << "\n";
    // FIXME: Catch exception in nested parsing, show useful debug output,
    // default to raw.
    try {
      ParserInput in{data, length};
      auto packet = Packet::create_or_throw(header->type(), in);
      packet->m_header = std::move(header);
      switch (packet->type()) {
        case PacketType::Marker:
          std::cout << ":marker packet: PGP\n";
          break;
        case PacketType::UserId: {
          auto uid = dynamic_cast<UserIdPacket*>(packet.get());
          assert(uid);
          const tao::json::value str = uid->m_content;
          std::cout << ":user ID packet: " << str << "\n";
        } break;
        case PacketType::PublicKey: {
          auto pubkey = dynamic_cast<PublicKeyPacket*>(packet.get());
          assert(pubkey);
          auto pub = dynamic_cast<PublicKeyData*>(pubkey->m_public_key.get());
          assert(pub);
          std::cout << ":public key packet:\n";
          output_public_key_data(pub);
        } break;
        case PacketType::PublicSubkey: {
          auto pubkey = dynamic_cast<PublicSubkeyPacket*>(packet.get());
          assert(pubkey);
          auto pub = dynamic_cast<PublicKeyData*>(pubkey->m_public_key.get());
          assert(pub);
          std::cout << ":public sub key packet:\n";
          output_public_key_data(pub);
        } break;
        case PacketType::Signature: {
          auto signature = dynamic_cast<SignaturePacket*>(packet.get());
          assert(signature);
          auto sig = dynamic_cast<SignatureData*>(signature->m_signature.get());
          assert(sig);
          std::cout << ":signature packet: algo "
                    << static_cast<int>(sig->public_key_algorithm()) << "\n";
          output_signature_data(sig);
        } break;
        default:
          break;
      }
    } catch (ParserError& exc) {
      exc.m_pos.m_byte += header->m_offset;
      std::cout << rang::style::bold << rang::fgB::red << "ERROR"
                << rang::style::reset << ":" << exc.what() << "\n";
    }
  }
  void start_packet(std::unique_ptr<PacketHeader> header){};
  void continue_packet(const char* data, size_t length){};
  void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                     const char* data, size_t length){};
};

static void process_msg(Botan::DataSource& source, Botan::DataSink& out) {
  out.start_msg();
  LegacyPacketSink sink;
  RawPacketParser parser(sink);
  parser.process(source);

  // Botan::secure_vector<uint8_t> buffer(Botan::DEFAULT_BUFFERSIZE);
  // while (!source.end_of_data()) {
  //   size_t got = source.read(buffer.data(), buffer.size());
  //   std::cerr << "XXX " << got << "\n";
  //   out.write(buffer.data(), got);
  // }
  out.end_msg();
}

void FilterPacketCommand::run() {
  Botan::DataSink_Stream out{std::cout};

  if (m_files.empty()) m_files.emplace_back("-");
  for (auto& file : m_files) {
    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      process_msg(in, out);
    } else {
      // Open in binary mode.
      Botan::DataSource_Stream in{file, true};
      process_msg(in, out);
    }
  }
}

PacketCommand::PacketCommand(CLI::App& app, const std::string& flag,
                             const std::string& description,
                             const std::string& group_name)
    : Command(app, flag, description, group_name),
      cmd_marker(m_cmd, "marker", "output a Marker Packet", group_write),
      cmd_uid(m_cmd, "uid", "output a User ID Packet", group_write),
      cmd_filter(m_cmd, "filter", "process packet data", group_process) {}

void PacketCommand::run() {
  if (m_cmd.get_subcommands().empty()) throw CLI::CallForHelp();
}

}  // Namespace NeoPG
