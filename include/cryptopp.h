#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "osrng.h"
#include <string>
#include "base64.h"
#include <cstdlib>
#include "cryptlib.h"
#include "hex.h"
#include "filters.h"
#include "aes.h"
#include "ccm.h"
#include "assert.h"
#include "arc4.h"
#include "secblock.h"
#include "files.h"


using namespace CryptoPP;
using std::string;
using CryptoPP::AES;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::CBC_Mode;
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;