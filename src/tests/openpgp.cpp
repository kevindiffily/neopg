#include <sstream>

#include "gtest/gtest.h"

#include "neopg/openpgp/tag.h"

using namespace NeoPG;

TEST(NeoPGTest, openpg_test) {
  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 3);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\x03");
  }

  {
    std::stringstream out;
    OpenPGP::OldPacketHeader tag(OpenPGP::PacketType::Marker, 3);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xa8\x03");
  }

  /* Examples from RFC 4880.  */
  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 100);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\x64");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 1723);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\xc5\xfb");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 100000);
    tag.write(out);
    ASSERT_EQ(out.str(), std::string("\xca\xff\x00\x01\x86\xa0", 6));
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 32768,
				 OpenPGP::PacketLengthType::Partial);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\xef");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 2,
				 OpenPGP::PacketLengthType::Partial);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\xe1");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 1,
				 OpenPGP::PacketLengthType::Partial);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\xe0");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 65536,
				 OpenPGP::PacketLengthType::Partial);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\xf0");
  }

  {
    std::stringstream out;
    OpenPGP::NewPacketHeader tag(OpenPGP::PacketType::Marker, 1693,
				 OpenPGP::PacketLengthType::TwoOctet);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xca\xc5\xdd");
  }

  /* Similar for old packet format, for comparison.  */
  {
    std::stringstream out;
    OpenPGP::OldPacketHeader tag(OpenPGP::PacketType::Marker, 100);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xa8\x64");
  }

  {
    std::stringstream out;
    OpenPGP::OldPacketHeader tag(OpenPGP::PacketType::Marker, 1723);
    tag.write(out);
    ASSERT_EQ(out.str(), "\xa9\x06\xbb");
  }

  {
    std::stringstream out;
    OpenPGP::OldPacketHeader tag(OpenPGP::PacketType::Marker, 100000);
    tag.write(out);
    ASSERT_EQ(out.str(), std::string("\xaa\x00\x01\x86\xa0", 5));
  }

}

