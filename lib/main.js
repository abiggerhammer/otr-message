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
    
  }

  /* Tagged plaintext messages, containing the "query" whitespace tag. */
  function tagged_plaintext() {

  }

  /* Ordinary plaintext, without the whitespace tag. */
  function plaintext() {

  }

  /* Error messages */
  function error() {

  }

  /* Base64-encoded binary messages */
  function encoded() {
    return this.choice(dh_commit, dh_key, reveal_signature, signature, v1_kem, data);
  }

  /* D-H Commit message, first message of the AKE. Bob commits to a choice
   * of D-H encryption key and sends this message to Alice, though he does
   * not reveal the key itself yet. */
  function dh_commit() {
     
  }

  /* D-H Key message, second message of the AKE. Alice sends her encryption
   * key to Bob.
   */
  function dh_key() {
     
  }

  /* Reveal Signature message, third message of the AKE. Bob reveals his D-H
   * encryption key and authenticates himself to Alice.
   */
  function reveal_signature() {
      
  }

  /* Signature message, final message of the AKE. Alice authenticates herself
   * and the channel parameters to Bob.
   */
  function signature() {
      
  }

  function v1_kem() {
      
  }

  /* Data message, used to transmit a private message or reveal old MAC keys. */
  function data() {
      
  }


});