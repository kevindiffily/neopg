// OpenPGP signature data (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_data.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_signature_data_test) {
  {
    // Test V3 packets.
    const std::string raw{
        "\x05\x10\x12\x34\x56\x78"
        "\xab\xcd\xef\xab\xcd\xef\xab\xcd"
        "\x01"
        "\x02"
        "\x67\x89"
        "\x00\x11\x01\x42\x23",
        23};
    ParserInput in(raw.data(), raw.length());
    auto signature = SignatureData::create_or_throw(SignatureVersion::V3, in);
    ASSERT_EQ(signature->version(), SignatureVersion::V3);
    auto v3sig = dynamic_cast<V2o3SignatureData*>(signature.get());
    ASSERT_NE(v3sig, nullptr);
    ASSERT_EQ(v3sig->m_type, static_cast<SignatureType>(0x10));
    ASSERT_EQ(v3sig->m_created, 0x12345678);
    // FIXME: check signer, quick
    ASSERT_EQ(v3sig->m_public_key_algorithm, PublicKeyAlgorithm::Rsa);
    ASSERT_EQ(v3sig->m_hash_algorithm, HashAlgorithm::Sha1);
#if 0
    ASSERT_NE(v3sig->m_signature, nullptr);
    ASSERT_EQ(v3sig->m_signature->algorithm(), PublicKeyAlgorithm::Rsa);
    auto rsa = dynamic_cast<RsaPublicKeyMaterial*>(v3sig->m_key.get());
    ASSERT_EQ(rsa->m_n, MultiprecisionInteger(0x14223));
    ASSERT_EQ(rsa->m_e, MultiprecisionInteger(0x3));
#endif
  }
}
