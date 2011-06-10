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

```
otr ::= query | error | encoded | tagged_plaintext | plaintext
query ::= query_prefix versions '?'
query_prefix ::= '?OTR'
versions ::= v1_p vN_p
v1_p ::= '?' | /* empty */
vN_p ::= 'v' versions
versions ::= version versions | /* empty */
version ::= otr_byte
tagged_plaintext ::= opt_string whitespace_tag opt_string
opt_string ::= string | /* empty */
whitespace_tag ::= mandatory_tag opt_v1_tag opt_v2_tag
mandatory_tag ::= 'x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
opt_v1_tag ::= '\x20\x09\x20\x09\x20\x20\x09\x20' | /* empty */
opt_v2_tag ::= '\x20\x20\x09\x09\x20\x20\x09\x20' | /* empty */
error ::= error_prefix string
error_prefix ::= '?OTR Error:'
plaintext ::= string opt_nul_tlv
opt_nul_tlv ::= '\x00' tlvs
tlvs ::= tlv tlvs | /* empty */
tlv ::= tlv_type tlv_length otr_byte{tlv_length_val}
tlv_type ::= '\x00\x00' | '\x00\x01'
tlv_length ::= otr_short
encoded ::= otr_prefix (dh_commit_msg | dh_key_msg | reveal_signature_msg | signature_msg | v1_ke_msg | data_msg) '.'
otr_prefix ::= '?OTR:'
otr_byte ::= char
otr_short ::= byte{2}
otr_int ::= byte{4}
otr_mpi ::= otr_int [^\x00]{otr_int_val}
otr_data ::= otr_int byte{otr_int_val}
otr_ctr ::= byte{8}
otr_mac ::= byte{20}
otr_pubkey ::= '\x00\x00' otr_mpi{4}
otr_sig ::= /* difficult, since this depends on an outside parameter... FIXME */
dh_commit_msg ::= '\x00\x02' 'x02' otr_data otr_data
dh_key_msg ::= '\x00\x02' '\x0a' otr_mpi
reveal_signature_msg ::= '\x00\x02' '\x11' otr_data otr_data otr_mac
signature_msg ::= '\x00\x02' '\x12' otr_data otr_mac
v1_ke_msg ::= FIXME
data_msg ::= '\x00\x02' '\x03' otr_byte otr_int otr_int otr_mpi otr_ctr otr_data otr_mac otr_data
```

## License ##

Copyright (c) 2011, Meredith L. Patterson &lt;clonearmy@gmail.com&gt;
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
