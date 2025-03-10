/*
* (C) 2025 LANCOM Systems GmbH Tim Wiechers
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/data_src.h>
#include <botan/ffi.h>
#include <botan/pkcs10.h>
#include <botan/internal/ffi_util.h>

#include <botan/internal/ffi_cert_ext.h>
#include <botan/internal/ffi_dn.h>
#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
BOTAN_FFI_DECLARE_STRUCT(botan_x509_csr_struct, Botan::PKCS10_Request, 0x17cfb333);
#endif

int botan_x509_csr_init(botan_x509_csr_t* out_csr,
                        botan_privkey_t key,
                        botan_x509_dn_t subject_dn,
                        botan_x509_exts_t exts,
                        const char* hash_name,
                        botan_rng_t rng,
                        const char* padding_scheme,
                        const char* challenge) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto csr = Botan::PKCS10_Request::create(
         safe_get(key), safe_get(subject_dn), safe_get(exts), hash_name, safe_get(rng), padding_scheme, challenge);

      auto csr_unique = std::make_unique<Botan::PKCS10_Request>(csr);

      *out_csr = new botan_x509_csr_struct(std::move(csr_unique));

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(out_csr, key, subject_dn, exts, hash_name, rng, padding_scheme, challenge);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_csr_destroy(botan_x509_csr_t csr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(csr);
#else
   BOTAN_UNUSED(csr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_csr_view_pem(botan_x509_csr_t csr, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(csr, [=](const auto& c) -> int { return invoke_view_callback(view, ctx, c.PEM_encode()); });
#else
   BOTAN_UNUSED(csr, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_csr_view_der(botan_x509_csr_t csr, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(csr, [=](const auto& c) -> int { return invoke_view_callback(view, ctx, c.BER_encode()); });
#else
   BOTAN_UNUSED(csr, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_csr_load(botan_x509_csr_t* out_csr, const uint8_t csr_bits[], size_t csr_bits_len) {
   if(!out_csr || !csr_bits) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(csr_bits, csr_bits_len);
      auto c = std::make_unique<Botan::PKCS10_Request>(bits);
      *out_csr = new botan_x509_csr_struct(std::move(c));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(out_csr, csr_bits, csr_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
