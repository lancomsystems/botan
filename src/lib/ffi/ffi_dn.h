/*
* (C) 2025 LANCOM Systems GmbH Tim Wiechers
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_DN_H_
#define BOTAN_FFI_DN_H_

#include <botan/pkix_types.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
extern "C" {
BOTAN_FFI_DECLARE_STRUCT(botan_x509_dn_struct, Botan::X509_DN, 0xdbc2116d);
}
#endif

#endif
