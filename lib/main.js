define(["require", "exports", "module"], function(require, exports. module) {
  exports.otr_message = otr_message;

  var ReParse = require('reparse');

  function parse(data) {
      return (new ReParse(data, true)).start(otr);
  }	   

  /* Root of OTR parser */
  function otr() {
      return this.choice(query, error, encoded, tagged_plaintext, plaintext);
  }

  /* Plaintext messages */
  /* Query messages */
  function query() {
      return this.seq(query_prefix, versions, /^\?/);
  }

  function query_prefix() {
      return this.match(/^\?OTR/);
  }

  function versions() {
      return this.seq(v1_p, vN_p);
  }
  
  function v1_p() {
      return this.maybe(/^\?/);
  }

  function vN_p() {
      return this.maybe(this.seq(/^v/), this.many(version));
  }

  /* Tagged plaintext messages, containing the "query" whitespace tag. */
  function tagged_plaintext() {
      return this.seq((this.maybe(string), whitespace_tag, this.maybe(string));
  }

  function whitespace_tag() {
      return this.seq(mandatory_tag, opt_v1_tag, opt_v2_tag);
  }

  function mandatory_tag() {
      return this.match(FIXME);
  }

  function opt_v1_tag() {
      return this.maybe(FIXME);
  }

  function opt_v2_tag() {
      return this.maybe(FIXME);
  }

  /* Error messages */
  function error() {
      return this.seq(error_prefix, string);
  }

  function error_prefix() {
      return this.match(/^\?OTR Error:/);
  }

  /* Ordinary plaintext, without the whitespace tag. */
  function plaintext() {
      return this.produce(string);
  }

  /* Base64-encoded binary messages */
  function encoded() {
      return this.seq(otr_prefix, this.choice(dh_commit, dh_key, reveal_signature, signature, v1_kem, data), /^\./);
  }

  function otr_prefix() {
      return this.match(/^\?OTR:/);
  }

  function otr_byte() {
      return this.match(FIXME); 
  }

  function otr_short() {
      var i = this.count(otr_byte, 2);
      return FIXME(i);
  }

  function otr_int() {
      var i = this.count(otr_byte, 4);
      return FIXME(i);
  }

  function otr_mpi() {
      var len = this.produce(otr_int);
      /* need to make sure that no leading zeroes, so otr_byte here is wrong. FIXME. */
      return this.count(otr_byte, len);
  }

  function otr_data() {
      var len = this.produce(otr_int);
      return this.count(otr_byte, len);
  }

  function otr_ctr() {
      return this.count(otr_byte, 8);
  }

  function otr_mac() {
      return this.count(otr_byte, 20);
  }

  function otr_pubkey() {
      return this.seq(otr_short, this.count(otr_mpi, 4));
  }

  function otr_sig(len) {
      return this.seq(this.count(otr_byte, len), this.count(otr_byte, len));
  }

  /* D-H Commit message, first message of the AKE. Bob commits to a choice
   * of D-H encryption key and sends this message to Alice, though he does
   * not reveal the key itself yet. */
  function dh_commit() {
      var version = this.produce(otr_short);
      var type = this.produce(otr_byte);
      var enc_gx = this.produce(otr_data);
      var hashed_gx = this.produce(otr_data);
      return FIXME;
  }

  /* D-H Key message, second message of the AKE. Alice sends her encryption
   * key to Bob.
   */
  function dh_key() {
      var version = this.produce(otr_short);
      var type = this.produce(otr_byte);
      var gy = this.produce(otr_mpi);
      return FIXME;
  }

  /* Reveal Signature message, third message of the AKE. Bob reveals his D-H
   * encryption key and authenticates himself to Alice.
   */
  function reveal_signature() {
      var version = this.produce(otr_short);
      var type = this.produce(otr_byte);
      var revealed_key = this.produce(otr_data);
      var enc_sig = this.produce(otr_data);
      var mac_sig = this.produce(otr_mac);
      return FIXME;
  }

  /* Signature message, final message of the AKE. Alice authenticates herself
   * and the channel parameters to Bob.
   */
  function signature() {
      var version = this.produce(otr_short);
      var type = this.produce(otr_byte);
      var enc_sig = this.produce(otr_data);
      var mac_sig = this.produce(otr_mac);
      return FIXME;
  }

  function v1_kem() {
      
  }

  /* Data message, used to transmit a private message or reveal old MAC keys. */
  function data() {
      var version = this.produce(otr_short);
      var type = this.produce(otr_byte);
      var flags = this.produce(otr_byte);
      var sender_keyid = this.produce(otr_int);
      var recip_keyid = this.produce(otr_int);
      var dh_y = this.produce(otr_int);
      var ctr_init = this.produce(otr_ctr);
      var enc_msg = this.produce(otr_data);
      var authenticator = this.produce(otr_mac);
      var old_mac_keys = this.produce(otr_data);
      return FIXME;
  }


});