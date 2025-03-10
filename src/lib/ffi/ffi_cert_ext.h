/*
* (C) 2025 LANCOM Systems GmbH Tim Wiechers
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_CERT_EXT_H_
#define BOTAN_FFI_CERT_EXT_H_

#include <botan/pkix_types.h>
#include <botan/x509_ext.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
extern "C" {
BOTAN_FFI_DECLARE_STRUCT(botan_x509_exts_struct, Botan::Extensions, 0xac898f09);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_ext_struct, Botan::Certificate_Extension, 0xb5ffd19c);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_basic_constraints_struct, Botan::Cert_Extension::Basic_Constraints, 0xe32de552);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_key_usage_struct, Botan::Cert_Extension::Key_Usage, 0x75cd7f05);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_extended_key_usage_struct, Botan::Cert_Extension::Extended_Key_Usage, 0x3d93aec6);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_subject_alt_name_struct,
                         Botan::Cert_Extension::Subject_Alternative_Name,
                         0x5cde8d21);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_alt_name_struct, Botan::AlternativeName, 0xe0f0d15c);
}
#endif

#endif
