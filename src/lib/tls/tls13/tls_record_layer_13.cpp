/*
* TLS record layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_record_layer_13.h>

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_version.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_reader.h>
#include <algorithm>

namespace Botan::TLS {

namespace {

template <typename IteratorT>
bool verify_change_cipher_spec(const IteratorT data, const size_t size) {
   // RFC 8446 5.
   //    An implementation may receive an unencrypted record of type
   //    change_cipher_spec consisting of the single byte value 0x01
   //    at any time [...]. An implementation which receives any other
   //    change_cipher_spec value or which receives a protected
   //    change_cipher_spec record MUST abort the handshake [...].
   const size_t expected_fragment_length = 1;
   const uint8_t expected_fragment_byte = 0x01;
   return (size == expected_fragment_length && *data == expected_fragment_byte);
}

Record_Type read_record_type(const uint8_t type_byte) {
   // RFC 8446 5.
   //    If a TLS implementation receives an unexpected record type,
   //    it MUST terminate the connection with an "unexpected_message" alert.
   if(type_byte != static_cast<uint8_t>(Record_Type::ApplicationData) &&
      type_byte != static_cast<uint8_t>(Record_Type::Handshake) &&
      type_byte != static_cast<uint8_t>(Record_Type::Alert) &&
      type_byte != static_cast<uint8_t>(Record_Type::ChangeCipherSpec)) {
      throw TLS_Exception(Alert::UnexpectedMessage, "TLS record type had unexpected value");
   }

   return static_cast<Record_Type>(type_byte);
}

/**
 * RFC 8446 5.1 `TLSPlaintext` without the `fragment` payload data
 */
class TLSPlaintext_Header final {
   public:
      TLSPlaintext_Header(std::vector<uint8_t> hdr, const bool check_tls13_version) {
         m_type = read_record_type(hdr[0]);
         m_legacy_version = Protocol_Version(make_uint16(hdr[1], hdr[2]));
         m_fragment_length = make_uint16(hdr[3], hdr[4]);
         m_serialized = std::move(hdr);

         // If no full version check is requested, we just verify the practically
         // ossified major version number.
         if(m_legacy_version.major_version() != 0x03) {
            throw TLS_Exception(Alert::IllegalParameter, "Received unexpected record version");
         }

         // RFC 8446 5.1
         //    legacy_record_version:  MUST be set to 0x0303 for all records
         //                            generated by a TLS 1.3 implementation
         if(check_tls13_version && m_legacy_version.version_code() != 0x0303) {
            throw TLS_Exception(Alert::IllegalParameter, "Received unexpected record version");
         }

         // RFC 8446 5.1
         //    Implementations MUST NOT send zero-length fragments of Handshake
         //    types, even if those fragments contain padding.
         //
         //    Zero-length fragments of Application Data MAY be sent, as they are
         //    potentially useful as a traffic analysis countermeasure.
         if(m_fragment_length == 0 && type() != Record_Type::ApplicationData) {
            throw TLS_Exception(Alert::DecodeError, "empty record received");
         }

         if(m_type == Record_Type::ApplicationData) {
            // RFC 8446 5.2
            //    The length [...] is the sum of the lengths of the content and the
            //    padding, plus one for the inner content type, plus any expansion
            //    added by the AEAD algorithm. The length MUST NOT exceed 2^14 + 256 bytes.
            //
            // Note: Limits imposed by a "record_size_limit" extension do not come
            //       into play here, as those limits are on the plaintext _not_ the
            //       encrypted data. Constricted devices must be able to deal with
            //       data overhead inflicted by the AEAD.
            if(m_fragment_length > MAX_CIPHERTEXT_SIZE_TLS13) {
               throw TLS_Exception(Alert::RecordOverflow, "Received an encrypted record that exceeds maximum size");
            }
         } else {
            // RFC 8446 5.1
            //    The length MUST NOT exceed 2^14 bytes.  An endpoint that receives a record that
            //    exceeds this length MUST terminate the connection with a "record_overflow" alert.
            //
            // RFC 8449 4.
            //    When the "record_size_limit" extension is negotiated, an endpoint
            //    MUST NOT generate a protected record with plaintext that is larger
            //    than the RecordSizeLimit value it receives from its peer.
            // -> Unprotected messages are not subject to this limit. <-
            if(m_fragment_length > MAX_PLAINTEXT_SIZE) {
               throw TLS_Exception(Alert::RecordOverflow, "Received a record that exceeds maximum size");
            }
         }
      }

      TLSPlaintext_Header(const Record_Type record_type,
                          const size_t frgmnt_length,
                          const bool use_compatibility_version) :
            m_type(record_type),
            m_legacy_version(use_compatibility_version ? 0x0301 : 0x0303)  // RFC 8446 5.1
            ,
            m_fragment_length(static_cast<uint16_t>(frgmnt_length)),
            m_serialized({
               static_cast<uint8_t>(m_type),
               m_legacy_version.major_version(),
               m_legacy_version.minor_version(),
               get_byte<0>(m_fragment_length),
               get_byte<1>(m_fragment_length),
            }) {}

      Record_Type type() const { return m_type; }

      uint16_t fragment_length() const { return m_fragment_length; }

      Protocol_Version legacy_version() const { return m_legacy_version; }

      const std::vector<uint8_t>& serialized() const { return m_serialized; }

   private:
      Record_Type m_type;
      Protocol_Version m_legacy_version;
      uint16_t m_fragment_length;
      std::vector<uint8_t> m_serialized;
};

}  // namespace

Record_Layer::Record_Layer(Connection_Side side) :
      m_side(side),
      m_outgoing_record_size_limit(MAX_PLAINTEXT_SIZE + 1 /* content type byte */),
      m_incoming_record_size_limit(MAX_PLAINTEXT_SIZE + 1 /* content type byte */)

      // RFC 8446 5.1
      //    legacy_record_version: MUST be set to 0x0303 for all records
      //       generated by a TLS 1.3 implementation other than an initial
      //       ClientHello [...], where it MAY also be 0x0301 for compatibility
      //       purposes.
      //
      // Additionally, older peers might send other values while requesting a
      // protocol downgrade. I.e. we need to be able to tolerate/emit legacy
      // values until we negotiated a TLS 1.3 compliant connection.
      //
      // As a client: we may initially emit the compatibility version and
      //              accept a wider range of incoming legacy record versions.
      // As a server: we start with emitting the specified legacy version of 0x0303
      //              but must also allow a wider range of incoming legacy values.
      //
      // Once TLS 1.3 is negotiateed, the implementations will disable these
      // compatibility modes accordingly or a protocol downgrade will transfer
      // the marshalling responsibility to our TLS 1.2 implementation.
      ,
      m_sending_compat_mode(m_side == Connection_Side::Client),
      m_receiving_compat_mode(true) {}

void Record_Layer::copy_data(std::span<const uint8_t> data) {
   m_read_buffer.insert(m_read_buffer.end(), data.begin(), data.end());
}

std::vector<uint8_t> Record_Layer::prepare_records(const Record_Type type,
                                                   std::span<const uint8_t> data,
                                                   Cipher_State* cipher_state) const {
   // RFC 8446 5.
   //    Note that [change_cipher_spec records] may appear at a point at the
   //    handshake where the implementation is expecting protected records.
   //
   // RFC 8446 5.
   //    An implementation which receives [...] a protected change_cipher_spec
   //    record MUST abort the handshake [...].
   //
   // ... hence, CHANGE_CIPHER_SPEC is never protected, even if a usable cipher
   // state was passed to this method.
   const bool protect = cipher_state != nullptr && type != Record_Type::ChangeCipherSpec;

   // RFC 8446 5.1
   BOTAN_ASSERT(protect || type != Record_Type::ApplicationData,
                "Application Data records MUST NOT be written to the wire unprotected");

   // RFC 8446 5.1
   //   "MUST NOT sent zero-length fragments of Handshake types"
   //   "a record with an Alert type MUST contain exactly one message" [of non-zero length]
   //   "Zero-length fragments of Application Data MAY be sent"
   BOTAN_ASSERT(!data.empty() || type == Record_Type::ApplicationData,
                "zero-length fragments of types other than application data are not allowed");

   if(type == Record_Type::ChangeCipherSpec && !verify_change_cipher_spec(data.begin(), data.size())) {
      throw Invalid_Argument("TLS 1.3 deprecated CHANGE_CIPHER_SPEC");
   }

   std::vector<uint8_t> output;

   // RFC 8446 5.2
   //    type:  The TLSPlaintext.type value containing the content type of the record.
   constexpr size_t content_type_tag_length = 1;

   // RFC 8449 4.
   //    When the "record_size_limit" extension is negotiated, an endpoint
   //    MUST NOT generate a protected record with plaintext that is larger
   //    than the RecordSizeLimit value it receives from its peer.
   //    Unprotected messages are not subject to this limit.
   const size_t max_plaintext_size =
      (protect) ? m_outgoing_record_size_limit - content_type_tag_length : static_cast<uint16_t>(MAX_PLAINTEXT_SIZE);

   const auto records = std::max((data.size() + max_plaintext_size - 1) / max_plaintext_size, size_t(1));
   auto output_length = records * TLS_HEADER_SIZE;
   if(protect) {
      // n-1 full records of size max_plaintext_size
      output_length +=
         (records - 1) * cipher_state->encrypt_output_length(max_plaintext_size + content_type_tag_length);
      // last record with size of remaining data
      output_length += cipher_state->encrypt_output_length(data.size() - ((records - 1) * max_plaintext_size) +
                                                           content_type_tag_length);
   } else {
      output_length += data.size();
   }
   output.reserve(output_length);

   size_t pt_offset = 0;
   size_t to_process = data.size();

   // For protected records we need to write at least one encrypted fragment,
   // even if the plaintext size is zero. This happens only for Application
   // Data types.
   BOTAN_ASSERT_NOMSG(to_process != 0 || protect);
   do {
      const size_t pt_size = std::min<size_t>(to_process, max_plaintext_size);
      const size_t ct_size =
         (!protect) ? pt_size : cipher_state->encrypt_output_length(pt_size + content_type_tag_length);
      const auto pt_type = (!protect) ? type : Record_Type::ApplicationData;

      // RFC 8446 5.1
      //    MUST be set to 0x0303 for all records generated by a TLS 1.3
      //    implementation other than an initial ClientHello [...], where
      //    it MAY also be 0x0301 for compatibility purposes.
      const auto record_header = TLSPlaintext_Header(pt_type, ct_size, m_sending_compat_mode).serialized();

      output.insert(output.end(), record_header.cbegin(), record_header.cend());

      auto pt_fragment = data.subspan(pt_offset, pt_size);
      if(protect) {
         secure_vector<uint8_t> fragment;
         fragment.reserve(ct_size);

         // assemble TLSInnerPlaintext structure
         fragment.insert(fragment.end(), pt_fragment.begin(), pt_fragment.end());
         fragment.push_back(static_cast<uint8_t>(type));
         // TODO: zero padding could go here, see RFC 8446 5.4

         cipher_state->encrypt_record_fragment(record_header, fragment);
         BOTAN_ASSERT_NOMSG(fragment.size() == ct_size);

         output.insert(output.end(), fragment.cbegin(), fragment.cend());
      } else {
         output.insert(output.end(), pt_fragment.begin(), pt_fragment.end());
      }

      pt_offset += pt_size;
      to_process -= pt_size;
   } while(to_process > 0);

   BOTAN_ASSERT_NOMSG(output.size() == output_length);
   return output;
}

Record_Layer::ReadResult<Record> Record_Layer::next_record(Cipher_State* cipher_state) {
   if(m_read_buffer.size() < TLS_HEADER_SIZE) {
      return TLS_HEADER_SIZE - m_read_buffer.size();
   }

   const auto header_begin = m_read_buffer.cbegin();
   const auto header_end = header_begin + TLS_HEADER_SIZE;

   // The first received record(s) are likely a client or server hello. To be able to
   // perform protocol downgrades we must be less vigorous with the record's
   // legacy version. Hence, `check_tls13_version` is `false` for the first record(s).
   TLSPlaintext_Header plaintext_header({header_begin, header_end}, !m_receiving_compat_mode);

   // After the key exchange phase of the handshake is completed and record protection is engaged,
   // cipher_state is set. At this point, only protected traffic (and CCS) is allowed.
   //
   // RFC 8446 2.
   //    -  Key Exchange: Establish shared keying material and select the
   //       cryptographic parameters.  Everything after this phase is
   //       encrypted.
   // RFC 8446 5.
   //    An implementation may receive an unencrypted [CCS] at any time
   if(cipher_state != nullptr && plaintext_header.type() != Record_Type::ApplicationData &&
      plaintext_header.type() != Record_Type::ChangeCipherSpec &&
      (!cipher_state->must_expect_unprotected_alert_traffic() || plaintext_header.type() != Record_Type::Alert)) {
      throw TLS_Exception(Alert::UnexpectedMessage, "unprotected record received where protected traffic was expected");
   }

   if(m_read_buffer.size() < TLS_HEADER_SIZE + plaintext_header.fragment_length()) {
      return TLS_HEADER_SIZE + plaintext_header.fragment_length() - m_read_buffer.size();
   }

   const auto fragment_begin = header_end;
   const auto fragment_end = fragment_begin + plaintext_header.fragment_length();

   if(plaintext_header.type() == Record_Type::ChangeCipherSpec &&
      !verify_change_cipher_spec(fragment_begin, plaintext_header.fragment_length())) {
      throw TLS_Exception(Alert::UnexpectedMessage, "malformed change cipher spec record received");
   }

   Record record(plaintext_header.type(), secure_vector<uint8_t>(fragment_begin, fragment_end));
   m_read_buffer.erase(header_begin, fragment_end);

   if(record.type == Record_Type::ApplicationData) {
      if(cipher_state == nullptr) {
         // This could also mean a misuse of the interface, i.e. failing to provide a valid
         // cipher_state to parse_records when receiving valid (encrypted) Application Data.
         throw TLS_Exception(Alert::UnexpectedMessage, "premature Application Data received");
      }

      if(record.fragment.size() < cipher_state->minimum_decryption_input_length()) {
         throw TLS_Exception(Alert::BadRecordMac, "incomplete record mac received");
      }

      if(cipher_state->decrypt_output_length(record.fragment.size()) > m_incoming_record_size_limit) {
         throw TLS_Exception(Alert::RecordOverflow, "Received an encrypted record that exceeds maximum plaintext size");
      }

      record.seq_no = cipher_state->decrypt_record_fragment(plaintext_header.serialized(), record.fragment);

      // Remove record padding (RFC 8446 5.4).
      const auto end_of_content =
         std::find_if(record.fragment.crbegin(), record.fragment.crend(), [](auto byte) { return byte != 0x00; });

      if(end_of_content == record.fragment.crend()) {
         // RFC 8446 5.4
         //   If a receiving implementation does not
         //   find a non-zero octet in the cleartext, it MUST terminate the
         //   connection with an "unexpected_message" alert.
         throw TLS_Exception(Alert::UnexpectedMessage, "No content type found in encrypted record");
      }

      // hydrate the actual content type from TLSInnerPlaintext
      record.type = read_record_type(*end_of_content);

      if(record.type == Record_Type::ChangeCipherSpec) {
         // RFC 8446 5
         //  An implementation [...] which receives a protected change_cipher_spec record MUST
         //  abort the handshake with an "unexpected_message" alert.
         throw TLS_Exception(Alert::UnexpectedMessage, "protected change cipher spec received");
      }

      // erase content type and padding
      record.fragment.erase((end_of_content + 1).base(), record.fragment.cend());
   }

   return record;
}

void Record_Layer::set_record_size_limits(const uint16_t outgoing_limit, const uint16_t incoming_limit) {
   BOTAN_ARG_CHECK(outgoing_limit >= 64, "Invalid outgoing record size limit");
   BOTAN_ARG_CHECK(incoming_limit >= 64 && incoming_limit <= MAX_PLAINTEXT_SIZE + 1,
                   "Invalid incoming record size limit");

   // RFC 8449 4.
   //    Even if a larger record size limit is provided by a peer, an endpoint
   //    MUST NOT send records larger than the protocol-defined limit, unless
   //    explicitly allowed by a future TLS version or extension.
   m_outgoing_record_size_limit = std::min(outgoing_limit, static_cast<uint16_t>(MAX_PLAINTEXT_SIZE + 1));
   m_incoming_record_size_limit = incoming_limit;
}

}  // namespace Botan::TLS
