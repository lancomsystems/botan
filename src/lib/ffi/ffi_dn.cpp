/*
* (C) 2025 LANCOM Systems GmbH Tim Wiechers
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ffi_util.h>

#include <botan/internal/ffi_dn.h>

extern "C" {

using namespace Botan_FFI;

int botan_x509_dn_init(botan_x509_dn_t* dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(dn == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto dn_unique = std::make_unique<Botan::X509_DN>();
      *dn = new botan_x509_dn_struct(std::move(dn_unique));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(dn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_destroy(botan_x509_dn_t dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(dn);
#else
   BOTAN_UNUSED(dn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_add_attribute(botan_x509_dn_t dn, const char* oid, const char* value) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](auto& name) {
      name.add_attribute(oid, value);
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(dn, oid, value);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_get_attributes(
   botan_x509_dn_t dn, const char* oid, size_t* out_len, char** out_values, size_t value_buf_size) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](const auto& name) {
      const auto values = name.get_attribute(oid);

      if(values.size() > *out_len) {
         return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
      }

      *out_len = values.size();

      for(size_t i = 0; i < values.size(); i++) {
         if(values[i].size() > value_buf_size) {
            return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         }

         for(size_t j = 0; j < values[i].size(); j++) {
            out_values[i][j] = values[i][j];
         }
      }

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(dn, oid, out_len, out_values, value_buf_size);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
