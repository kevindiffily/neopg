// OpenPGP public key packet data (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/public_key_data.h>

#include <neopg/v3_public_key_data.h>
#include <neopg/v4_public_key_data.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

std::unique_ptr<PublicKeyData> PublicKeyData::create_or_throw(
    PublicKeyVersion version, ParserInput& in) {
  // std::string orig_data{in.current(), in.size()};

  std::unique_ptr<PublicKeyData> public_key;
  switch (version) {
    case PublicKeyVersion::V2:
    case PublicKeyVersion::V3:
      public_key = V3PublicKeyData::create_or_throw(in);
      break;
    case PublicKeyVersion::V4:
      public_key = V4PublicKeyData::create_or_throw(in);
      break;
    default:
      in.error("unknown public key version");
  }
  if (in.size() != 0) in.error("trailing data in public key");

  // FIXME: We could now output the public_key and verify that it outputs to
  // exactly the same bytes as the original data.  This will make sure we can
  // calculate the fingerprint correctly.
  // std::stringstream out;
  // public_key->write(out);
  // assert(orig_data == out.str());
  return public_key;
}
