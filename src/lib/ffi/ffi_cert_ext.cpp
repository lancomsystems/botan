/*
* (C) 2025 LANCOM Systems GmbH Tim Wiechers
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>

#include <botan/internal/ffi_cert_ext.h>
#include <botan/internal/ffi_dn.h>

/*
* Searches an extension by type and casts it into the FFI type.
*/
template <class CertExtension_t, typename ffi_t, typename ffi_struct>
int get_extension(ffi_t* out_ext, botan_x509_exts_t exts) {
   if(out_ext == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(exts, [=](const auto& extensions) {
      // we cannot use "get_extension_object_as()", since we need a unique_ptr
      // const CertExtension_t* ext = extensions.template get_extension_object_as<CertExtension_t>();

      // so use "get()", and cast the pointer type
      std::unique_ptr<Botan::Certificate_Extension> generic_ext_ptr = extensions.get(CertExtension_t::static_oid());
      if(generic_ext_ptr == nullptr) {
         return BOTAN_FFI_SUCCESS;
      }

      // releasing this unique_ptr is okay, since "get()" returns a copy of the extension
      auto ext_ptr = std::unique_ptr<CertExtension_t>{static_cast<CertExtension_t*>(generic_ext_ptr.release())};

      *out_ext = new ffi_struct(std::move(ext_ptr));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(out_ext, exts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

extern "C" {

using namespace Botan_FFI;

int botan_x509_exts_init(botan_x509_exts_t* exts) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(exts == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto extn = std::make_unique<Botan::Extensions>();
      *exts = new botan_x509_exts_struct(std::move(extn));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(exts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_exts_destroy(botan_x509_exts_t exts) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(exts);
#else
   BOTAN_UNUSED(exts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_exts_add_or_replace(botan_x509_exts_t exts, botan_x509_cert_ext_t ext, int is_critical) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(exts, [=](auto& extensions) {
      // here we cannot use "safe_get()" because we actually pass in subclasses of "botan_x509_cert_ext_t",
      // and the magic number will not match
      bool is_set = extensions.extension_set(ext->unsafe_get()->oid_of());

      auto new_unique_ptr = ext->unsafe_get()->copy();

      if(is_set) {
         extensions.replace(std::move(new_unique_ptr), is_critical);
      } else {
         extensions.add(std::move(new_unique_ptr), is_critical);
      }

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(exts, ext, is_critical);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_exts_is_critical(botan_x509_exts_t exts, botan_x509_cert_ext_t ext, int* out_is_critical) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(exts, [=](const auto& extensions) {
      *out_is_critical = extensions.critical_extension_set(ext->unsafe_get()->oid_of());
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(exts, ext, out_is_critical);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_basic_constraints_init(botan_x509_basic_constraints_t* ext, int is_ca, size_t path_limit) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ext == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto ext_ptr = std::make_unique<Botan::Cert_Extension::Basic_Constraints>(is_ca, path_limit);
      *ext = new botan_x509_basic_constraints_struct(std::move(ext_ptr));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ext, is_ca, path_limit);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_basic_constraints_destroy(botan_x509_basic_constraints_t ext) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ext);
#else
   BOTAN_UNUSED(ext);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_basic_constraints_is_ca(botan_x509_basic_constraints_t ext, int* out_is_ca) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(ext, [=](const auto& bc) {
      *out_is_ca = bc.get_is_ca();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ext, out_is_ca);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_basic_constraints_path_limit(botan_x509_basic_constraints_t ext, size_t* out_path_limit) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(ext, [=](const auto& bc) {
      *out_path_limit = bc.get_path_limit();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ext, out_path_limit);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_basic_constraints_get(botan_x509_basic_constraints_t* out_ext, botan_x509_exts_t exts) {
   return get_extension<Botan::Cert_Extension::Basic_Constraints,
                        botan_x509_basic_constraints_t,
                        botan_x509_basic_constraints_struct>(out_ext, exts);
}

int botan_x509_ext_key_usage_init(botan_x509_key_usage_t* out_ext, uint32_t constraints) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(out_ext == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto ext_ptr = std::make_unique<Botan::Cert_Extension::Key_Usage>(Botan::Key_Constraints(constraints));
      *out_ext = new botan_x509_key_usage_struct(std::move(ext_ptr));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(out_ext, constraints);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_key_usage_destroy(botan_x509_key_usage_t ext) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ext);
#else
   BOTAN_UNUSED(ext);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_key_usage_constraints(botan_x509_key_usage_t ext, uint32_t* out_constraints) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(ext, [=](const auto& ku) {
      *out_constraints = ku.get_constraints().value();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ext, out_constraints);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_key_usage_get(botan_x509_key_usage_t* out_ext, botan_x509_exts_t exts) {
   return get_extension<Botan::Cert_Extension::Key_Usage, botan_x509_key_usage_t, botan_x509_key_usage_struct>(out_ext,
                                                                                                               exts);
}

int botan_x509_ext_extended_key_usage_init(botan_x509_extended_key_usage_t* out_ext, char* oids[], size_t oids_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(out_ext == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      std::vector<Botan::OID> oid_vector;
      for(size_t i = 0; i < oids_len; i++) {
         oid_vector.push_back(Botan::OID::from_string(oids[i]));
      }

      auto ext_ptr = std::make_unique<Botan::Cert_Extension::Extended_Key_Usage>(oid_vector);
      *out_ext = new botan_x509_extended_key_usage_struct(std::move(ext_ptr));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(out_ext, constraints);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_extended_key_usage_destroy(botan_x509_extended_key_usage_t ext) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ext);
#else
   BOTAN_UNUSED(ext);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_extended_key_usage_contains(botan_x509_extended_key_usage_t ext, int* out_contains_oid, char* oid) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(ext, [=](const auto& eku) {
      const auto v = eku.object_identifiers();
      if(std::find(v.begin(), v.end(), Botan::OID::from_string(oid)) == v.end()) {
         *out_contains_oid = 0;
      } else {
         *out_contains_oid = 1;
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ext, out_contains_oid, oid);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_extended_key_usage_get(botan_x509_extended_key_usage_t* out_ext, botan_x509_exts_t exts) {
   return get_extension<Botan::Cert_Extension::Extended_Key_Usage,
                        botan_x509_extended_key_usage_t,
                        botan_x509_extended_key_usage_struct>(out_ext, exts);
}

int botan_x509_alt_name_init(botan_x509_alt_name_t* out_alt_name) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto name_ptr = std::make_unique<Botan::AlternativeName>();
      *out_alt_name = new botan_x509_alt_name_struct(std::move(name_ptr));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(out_alt_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alt_name_destroy(botan_x509_alt_name_t alt_name) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(alt_name);
#else
   BOTAN_UNUSED(alt_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alt_name_add_attribute(botan_x509_alt_name_t alt_name, char* type, char* value) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_name, [=](auto& an) {
      an.add_attribute(type, value);
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(alt_name, type, value);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alt_name_add_dir(botan_x509_alt_name_t alt_name, botan_x509_dn_t dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_name, [=](auto& an) {
      auto dn_clone = Botan::X509_DN();

      auto attrs = safe_get(dn).get_attributes();
      for(auto itr = attrs.begin(); itr != attrs.end(); itr++) {
         dn_clone.add_attribute(itr->first, itr->second);
      }

      an.add_dn(dn_clone);
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(alt_name, dn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alt_name_get_attribute(
   botan_x509_alt_name_t alt_name, char* type, size_t* out_len, char** out_values, size_t value_buf_size) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_name, [=](const auto& an) {
      const auto values = an.get_attribute(type);

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
   BOTAN_UNUSED(alt_name, type, out_len, out_values, value_buf_size);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alt_name_get_dir(botan_x509_alt_name_t alt_name, size_t* out_len, botan_x509_dn_t* out_values) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_name, [=](const auto& an) {
      const auto names = an.directory_names();

      if(names.size() > *out_len) {
         return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
      }

      *out_len = names.size();

      int i = 0;
      for(const Botan::X509_DN name : names) {
         auto name_ptr = std::make_unique<Botan::X509_DN>(name.contents());
         out_values[i] = new botan_x509_dn_struct(std::move(name_ptr));
         i++;
      }

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(alt_name, out_len, out_values);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_subject_alt_name_init(botan_x509_subject_alt_name_t* out_ext, botan_x509_alt_name_t alt_name) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_name, [=](const auto& an) {
      auto name_clone = Botan::AlternativeName();

      auto attrs = an.get_attributes();
      for(auto itr = attrs.begin(); itr != attrs.end(); itr++) {
         name_clone.add_attribute(itr->first, itr->second);
      }

      auto ext_ptr = std::make_unique<Botan::Cert_Extension::Subject_Alternative_Name>(name_clone);
      *out_ext = new botan_x509_subject_alt_name_struct(std::move(ext_ptr));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(out_ext, alt_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_subject_alt_name_destroy(botan_x509_subject_alt_name_t ext) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ext);
#else
   BOTAN_UNUSED(ext);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_subject_alt_name_name(botan_x509_subject_alt_name_t ext, botan_x509_alt_name_t* out_alt_name) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(ext, [=](const auto& san) {
      auto name_clone = Botan::AlternativeName();

      auto attrs = san.get_alt_name().get_attributes();
      for(auto itr = attrs.begin(); itr != attrs.end(); itr++) {
         name_clone.add_attribute(itr->first, itr->second);
      }

      auto name_ptr = std::unique_ptr<Botan::AlternativeName>(new Botan::AlternativeName(name_clone));
      *out_alt_name = new botan_x509_alt_name_struct(std::move(name_ptr));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ext, out_alt_name);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_subject_alt_name_get(botan_x509_subject_alt_name_t* out_ext, botan_x509_exts_t exts) {
   return get_extension<Botan::Cert_Extension::Subject_Alternative_Name,
                        botan_x509_subject_alt_name_t,
                        botan_x509_subject_alt_name_struct>(out_ext, exts);
}
}
