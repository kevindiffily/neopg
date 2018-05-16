// OpenPGP public key material (tests)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_material.h>

#include <gtest/gtest.h>

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_public_key_material_test) {
  {
    const auto raw = std::string{"\x00\x09\x01\x62\x00\x02\x03", 7};

    ParserInput in(raw.data(), raw.length());
    auto rsa_ptr = RsaPublicKeyMaterial::create_or_throw(in);
    ASSERT_EQ(in.size(), 0);

    RsaPublicKeyMaterial& rsa{*rsa_ptr};
    ASSERT_EQ(rsa.algorithm(), PublicKeyAlgorithm::Rsa);
    ASSERT_EQ(rsa.m_n, MultiprecisionInteger(0x162));
    ASSERT_EQ(rsa.m_e, MultiprecisionInteger(3));

    std::stringstream out;
    rsa.write(out);
    ASSERT_EQ(out.str(), raw);
  }

  {
    const auto raw =
        std::string{"\x00\x09\x01\x62\x00\x02\x03\x00\x02\x02", 10};
    ParserInput in1(raw.data(), raw.length());
    ASSERT_NO_THROW(RsaPublicKeyMaterial::create_or_throw(in1));
    ASSERT_EQ(in1.position(), 7);

    ParserInput in2(raw.data(), raw.length() - 6);
    ASSERT_ANY_THROW(RsaPublicKeyMaterial::create_or_throw(in2));

    ParserInput in3(raw.data(), raw.length() - 3);
    in3.bump(4);
    ASSERT_ANY_THROW(RsaPublicKeyMaterial::create_or_throw(in3));
  }

  {
    const auto raw =
        std::string{"\x00\x09\x01\x62\x00\x02\x03\x00\x02\x02\x00\x01\x01", 13};

    ParserInput in(raw.data(), raw.length());
    auto dsa_ptr = DsaPublicKeyMaterial::create_or_throw(in);
    ASSERT_EQ(in.size(), 0);

    DsaPublicKeyMaterial& dsa{*dsa_ptr};
    ASSERT_EQ(dsa.algorithm(), PublicKeyAlgorithm::Dsa);
    ASSERT_EQ(dsa.m_p, MultiprecisionInteger(0x162));
    ASSERT_EQ(dsa.m_q, MultiprecisionInteger(3));
    ASSERT_EQ(dsa.m_g, MultiprecisionInteger(2));
    ASSERT_EQ(dsa.m_y, MultiprecisionInteger(1));

    std::stringstream out;
    dsa.write(out);
    ASSERT_EQ(out.str(), raw);
  }

  {
    const auto raw =
        std::string{"\x00\x09\x01\x62\x00\x02\x03\x00\x02\x02", 10};

    ParserInput in(raw.data(), raw.length());
    auto elgamal_ptr = ElgamalPublicKeyMaterial::create_or_throw(in);
    ASSERT_EQ(in.size(), 0);

    ElgamalPublicKeyMaterial& elgamal{*elgamal_ptr};
    ASSERT_EQ(elgamal.algorithm(), PublicKeyAlgorithm::Elgamal);
    ASSERT_EQ(elgamal.m_p, MultiprecisionInteger(0x162));
    ASSERT_EQ(elgamal.m_g, MultiprecisionInteger(3));
    ASSERT_EQ(elgamal.m_y, MultiprecisionInteger(2));

    std::stringstream out;
    elgamal.write(out);
    ASSERT_EQ(out.str(), raw);
  }
}
