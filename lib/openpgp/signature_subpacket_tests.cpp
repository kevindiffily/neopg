// OpenPGP signature subpacket (tests)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/signature_subpacket.h>

#include "gtest/gtest.h"

#include <memory>
#include <sstream>

using namespace NeoPG;

TEST(NeopgTest, openpgp_signature_subpacket_test) {
  {
    std::stringstream out;
    RawSignatureSubpacket packet(SignatureSubpacketType::SignatureCreationTime,
                                 std::string("\x12\x34\x56\x78", 4));
    packet.write(out);
    ASSERT_EQ(out.str(), std::string("\x05\x02\x12\x34\x56\x78", 6));
  }
}
