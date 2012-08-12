#include <hammer.h>

#define false 0
#define true 1

bool validate_v1_ke_msg(HParseResult *p) {
  if (TT_SEQUENCE != p->ast->token_type)
    return false;
  /* The fifth element in this sequence is the four parameters of the DSA public key. We want the second one, q.
   * The eighth is the DSA signature and its length must be 2*q.
   */
  HParsedToken *pubkey = p->ast->seq->elements[4];
  HParsedToken *q = pubkey->seq->elements[1];
  // FIXME get the bignum out of q
  HParsedToken *sig = p->ast->seq->elements[9];
  if (TT_BYTES != sig->token_type)
    return false;
  return (sig->bytes.len == 2*unpack_mpi(q->seq));
}

bool validate_old_macs(HParseResult *p);

bool validate_data_mac(HParseResult *p);

const HParsedToken* get_smp_tlvs(const HParseResult *t);

const HParser* init_parser() {
  static const HParser *otr_message = NULL;
  if (otr_message)
    return otr_message;

  /**
   * OTR primitives 
   */
  /* derp, we need to be able to get the value out of this. Bignums, oh boy */
  const HParser *otr_mpi = h_length_value(h_uint32(),
					  h_uint8());

  const HParser *otr_data = h_length_value(h_uint32(),
					   h_uint8());

  const HParser *otr_ctr = h_repeat_n(h_uint8(), 8);
  
  const HParser *otr_mac = h_repeat_n(h_uint8(), 20);

  const HParser *otr_this_version = h_int_range(h_uint16(), 2, 2);

  /**
   * OTR query messages
   */
  const HParser *otr_query = NULL;
  const HParser *otr_prefix = h_token((const uint8_t*)"?OTR", 4);

  const HParser *v1_p = h_optional(h_ch('?'));

  const HParser *vN_p = h_sequence(h_ch('v'),
				   h_many(h_not_in("?", 1)),
				   NULL);

  const HParser *versions = h_sequence(v1_p,
				       vN_p,
				       NULL);

  otr_query = h_sequence(otr_prefix,
			 versions,
			 h_ch('?'),
			 NULL);

  /**
   * OTR error messages 
   */
  const HParser *otr_error = NULL;

  const HParser *error_prefix = h_token((const uint8_t*)"?OTR Error", 9);

  otr_error = h_sequence(error_prefix,
			 h_many(h_uint8()),
			 NULL);
  
  /**
   * OTR encoded messages 
   */
  const HParser *otr_encoded = NULL;

  const HParser *dh_commit_msg = h_sequence(otr_this_version,
					    h_int_range(h_uint8(), 2, 2),
					    otr_data,
					    otr_data,
					    NULL);

  const HParser *dh_key_msg = h_sequence(otr_this_version,
					 h_int_range(h_uint8(), '\x0a', '\x0a'),
					 otr_mpi,
					 NULL);
  
  const HParser *reveal_signature_msg = h_sequence(otr_this_version,
						   h_int_range(h_uint8(), '\x11', '\x11'),
						   otr_data,
						   otr_data,
						   otr_mac,
						   NULL);

  const HParser *signature_msg = h_sequence(otr_this_version,
					    h_int_range(h_uint8(), '\x12', '\x12'),
					    otr_data,
					    otr_mac,
					    NULL);

  /* This is not exactly right -- everything between the prefix and the period is base64'ed */
  const HParser *v1_ke_msg = h_attr_bool(h_sequence(otr_prefix,
						    h_int_range(h_uint16(), 1, 1),
						    h_int_range(h_uint8(), '\x0a', '\x0a'),
						    h_int_range(h_uint8(), 0, 1),
						    h_repeat_n(otr_mpi, 4),
						    h_uint32(),
						    otr_mpi,
						    h_many1(h_uint8()),
						    h_ch('.'),
						    NULL),
					 validate_v1_ke_msg);
				
  const HParser *data_msg = h_attr_bool(h_sequence(otr_this_version,
						   h_int_range(h_uint8(), 3, 3),
						   h_int_range(h_uint8(), 0, 1),
						   h_int_range(h_uint32(), 1, UINT_MAX),
						   h_int_range(h_uint32(), 1, UINT_MAX),
						   otr_mpi,
						   otr_ctr,
						   otr_data,
						   otr_mac,
						   h_attr_bool(otr_data,
							       validate_old_macs),
						   NULL),
					validate_data_mac);

  /* TLVs, will be used in data_msg eventually */
  const HParser *base_tlv = h_sequence(h_int_range(h_uint16(), 0, 1),
				       h_length_value(h_uint16(), h_uint8()),
				       NULL);

  const HParser *smp_tlv = h_sequence(h_int_range(h_uint16(), 2, 6),
				      h_action(h_length_value(h_uint16(), h_uint8()),
					       get_smp_tlvs),
				      NULL);

  const HParser *otr_tlv = h_choice(base_tlv,
				    smp_tlv,
				    NULL);

  const HParser *plaintext = h_sequence(h_many1(h_not_in("\x00", 1)), // not actually right, that should be "utf8"
					h_optional(h_sequence(h_ch('\x00'),
							      h_many(otr_tlv),
							      NULL)),
					NULL);					
 
  otr_encoded = h_sequence(otr_prefix,
			   h_choice(dh_commit_msg,
				    dh_key_msg,
				    reveal_signature_msg,
				    signature_msg,
				    v1_ke_msg,
				    data_msg,
				    NULL),
			   NULL);

  /**
   * OTR tagged plaintext messages 
   */
  const HParser *otr_tagged_plaintext = NULL;

  const HParser *whitespace_magic = h_token((const uint8_t*)"\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20", 16);

  const HParser *whitespace_v1_tag = h_token((const uint8_t*)"\x20\x09\x20\x09\x20\x20\x09\x20", 8);

  const HParser *whitespace_v2_tag = h_token((const uint8_t*)"\x20\x20\x09\x09\x20\x20\x09\x20", 8);

  const HParser *whitespace_tag = h_sequence(whitespace_magic,
					     h_optional(whitespace_v1_tag),
					     h_optional(whitespace_v2_tag),
					     NULL);

  otr_tagged_plaintext = h_sequence(h_optional(h_many(h_uint8())), // this may get us into trouble with greediness :-/
				    whitespace_tag,
				    h_optional(h_many(h_uint8())),
				    NULL);
  
  otr_message = h_sequence(h_choice(otr_query,
				    otr_error,
				    otr_encoded,
				    otr_tagged_plaintext,
				    NULL),
			   h_end_p(),
			   NULL);

}
