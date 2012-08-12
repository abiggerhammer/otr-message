# otr-message #

otr-message is a Javascript parser for the message format used in the [Off-the-Record Messaging](http://www.cypherpunks.ca/otr/) instant messaging encryption system, [version 2](http://www.cypherpunks.ca/otr/Protocol-v2-3.0.0.html).

## Installation ##

Coming soon. FIXME

### Dependencies ###
ReParse. Or possibly the Javascript port of Parsec. Watch this space for updates.

## API ##

Coming soon. FIXME

## Grammar ##

otr-message uses the following (incomplete!) grammar to describe the format of OTR messages:

BASE_64(...) is a base64 representation of its arguments
VALUE(field[n]) is the value of the nth field in this rule, to be used as an attribute. n indexes from 0.
AES128_CTR(...) is the AES-128 encryption of its arguments in counter mode. I don't know whether we should represent encryption *parameters* in this attribute representation or not; "generation is parsing backward" doesn't exactly apply when your attribute functions are one-way :(

```
otr ::= query | error | encoded | tagged_plaintext | plaintext
query ::= query_prefix versions '?'
query_prefix ::= '?OTR'
versions ::= v1_p vN_p
v1_p ::= ['?']
vN_p ::= 'v' *otr_byte
tagged_plaintext ::= [string] whitespace_tag [string]
whitespace_tag ::= 'x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20' [v1_tag] [v2_tag]
error ::= error_prefix string
error_prefix ::= '?OTR Error:'
plaintext ::= utf8 [otr_byte(0x00) *tlv]
tlv ::= base_tlv | smp_tlv
base_tlv ::= otr_short(0x0000 | 0x0001) tlv_length VALUE(field[1])*VALUE(field[1])otr_byte
smp_tlv ::= otr_short(0x0002 | 0x0003 | 0x0004 | 0x0005 | 0x0006) tlv_length smp_tlv_data
// the length of smp_tlv_data is tlv_length
smp_tlv_data ::= otr_int VALUE(field[0])*VALUE(field[0])otr_mpi
tlv_length ::= otr_short
encoded ::= otr_prefix BASE64(dh_commit_msg | dh_key_msg | reveal_signature_msg | signature_msg | v1_ke_msg | data_msg) '.'
otr_prefix ::= '?OTR:'
otr_byte ::= char
otr_short ::= 2*2byte
otr_int ::= 4*4byte
otr_mpi ::= otr_int VALUE(field[0])*VALUE(field[0])otr_byte([^\x00])
otr_data ::= otr_int VALUE(field[0])*VALUE(field[0])otr_byte
otr_ctr ::= 8*8byte
otr_mac ::= 20*20byte
otr_pubkey ::= otr_short(0x0000) otr_mpi otr_mpi(20) 2*2otr_mpi
otr_sig(k) ::= otr_data(AES128_CTR(k, otr_pubkey otr_int 2*2(VALUE(field[0][1])*VALUE(field[0][1])otr_byte)
dh_commit_msg ::= otr_short(0x0002) otr_byte(0x02) otr_data(AES128_CTR(otr_mpi)) otr_data(32)
dh_key_msg ::= otr_short(0x0002) otr_byte(0x0a) otr_mpi
// TODO: g^y, the MPI in dh_key_msg, is supposed to have a y at least 320 bits. meaningful here?
reveal_signature_msg ::= otr_short(0x0002) otr_byte(0x11) otr_data(16) otr_sig(c) otr_mac
// the third field of reveal_signature_msg is a 128-bit value, so 16 bytes encoded as otr_data
// the key c is computed from the Diffie-Hellman shared secret s, which we compute from the value we got in step 2 of the AKE.
signature_msg ::= otr_short(0x0002) otr_byte(0x12) otr_sig(c') otr_mac
// the key c' is computed from s, but with a different procedure than for reveal_signature_message
v1_ke_msg ::= otr_prefix BASE_64(otr_short(0x0001) otr_byte(0x0a) otr_byte(0x01 | 0x00) 4*4otr_mpi otr_int otr_mpi 2*2byte(VALUE(field[4]))
// The second otr_byte of v1_ke_msg is 0x01 if this message is being sent in reply to a key exchange message that was just
// received. That probably belongs in the state machine.
data_msg ::= otr_short(0x0002) otr_byte(0x03) otr_byte(0x00 | 0x01) otr_int(>0) otr_int(>0) otr_mpi otr_ctr otr_data(AES128_CTR(plaintext) otr_mac(VALUE(field[0...7])) otr_data(0*2otr_mac)
// The third field is for flags, of which one is defined, IGNORE_UNREADABLE (0x01)
// The fourth field must increment by 1 with each key change
```

## License ##

Copyright (c) 2011-2012, Meredith L. Patterson &lt;mlp@thesmartpolitenerd.com&gt;
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

* Neither the name of the <organization> nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT
HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
