
..
   Copyright 2017-2018 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS <cedric@ledger.fr>
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

..
   ------------------------------------------------------------------------
                         LaTex substitution Definition
   ------------------------------------------------------------------------

.. |_pb|    replace:: :math:`\pagebreak`

.. |spk|    replace:: :math:`\mathit{spk}`
.. |espk|   replace:: :math:`\widetilde{\mathit{spk}}`
.. |enc|    replace:: :math:`\mathtt{AES}`
.. |dec|    replace:: :math:`\mathtt{AES^{-1}}`

.. |A|      replace:: :math:`\mathit{A}`
.. |aa|     replace:: :math:`\mathit{a}`
.. |a.A|    replace:: :math:`(\mathit{a, A})`
.. |C|      replace:: :math:`\mathit{C}`
.. |c|      replace:: :math:`\mathit{c}`

.. |B|      replace:: :math:`\mathit{B}`
.. |bb|     replace:: :math:`\mathit{b}`
.. |b.B|    replace:: :math:`(\mathit{b, B})`
.. |D|      replace:: :math:`\mathit{D`
.. |d|      replace:: :math:`\mathit{d_{i}}`
.. |ed|     replace:: :math:`\widetilde{\mathit{d_{i}}}`


.. |c|      replace:: :math:`\mathit{c}`
.. |c.C|    replace:: :math:`(\mathit{c, C})`
.. |d|      replace:: :math:`\mathit{d}`
.. |d.D|    replace:: :math:`(\mathit{d, D})`
.. |Aout|   replace:: :math:`\mathit{A_{out}}`
.. |Bout|   replace:: :math:`\mathit{B_{out}}`
.. |Dout|   replace:: :math:`\mathit{D_{out}}`
.. |Cout|   replace:: :math:`\mathit{C_{out}}`


.. |x|      replace:: :math:`\mathit{x}`
.. |ex|     replace:: :math:`\widetilde{\mathit{x}}`
.. |x1|     replace:: :math:`\mathit{x}`
.. |ex1|    replace:: :math:`\widetilde{\mathit{x}}`
.. |x2|     replace:: :math:`\mathit{x}`
.. |ex2|    replace:: :math:`\widetilde{\mathit{x}}`
.. |P|      replace:: :math:`\mathit{P}`
.. |xP|     replace:: :math:`\mathit{xP}`
.. |G|      replace:: :math:`\mathit{G}`
.. |xG|     replace:: :math:`\mathit{xG}`
.. |order|  replace:: :math:`\mathtt{\#n}`

.. |Tin|    replace:: :math:`\mathit{T_{in}}`
.. |Tout|   replace:: :math:`\mathit{T_{out}}`

.. |s|      replace:: :math:`\mathit{s}`
.. |es|     replace:: :math:`\widetilde{\mathit{s}}`

.. |Img|     replace:: :math:`\mathit{Img(P)}`

.. |Drv|    replace:: :math:`\mathfrak{D}_\mathrm{in}`
.. |eDrv|   replace:: :math:`\widetilde{\mathfrak{D}_\mathrm{in}}`

.. |Rin|    replace:: :math:`\mathit{R_{in}}`
.. |R|      replace:: :math:`\mathit{R}`
.. |rr|     replace:: :math:`\mathit{r}`
.. |r.R|    replace:: :math:`(\mathit{r, R})`

.. |PayID|  replace:: :math:`\mathit{PayID}`
.. |ePayID| replace:: :math:`\widetilde{\mathit{PayID}}`
.. |Ct|     replace:: :math:`\mathit{C_v}`
.. |Ctf|    replace:: :math:`\mathit{C_v = k.G + v.H}`
.. |H|      replace:: :math:`\mathit{H}`
.. |h|      replace:: :math:`\mathit{h}`
.. |Hf|     replace:: :math:`\mathit{H = h.G}`
.. |l|      replace:: :math:`\mathit{l}`
.. |v|      replace:: :math:`\mathit{v}`
.. |k|      replace:: :math:`\mathit{k}`
.. |ev|     replace:: :math:`\widetilde{\mathit{v}}`
.. |ek|     replace:: :math:`\widetilde{\mathit{k}}`
.. |xin|    replace:: :math:`\mathit{x_{in}}`
.. |Pin|    replace:: :math:`\mathit{P_{in}}`
.. |xPin|   replace:: :math:`(\mathit{x_{in}, P_{in}})`
.. |exin|   replace:: :math:`\widetilde{\mathit{x_{in}}}`
.. |Pout|   replace:: :math:`\mathit{P_{out}}`
.. |ai|     replace:: :math:`\mathit{\alpha_{in}}`
.. |eai|    replace:: :math:`\widetilde{\mathit{\alpha_{in}}}`
.. |aGi|    replace:: :math:`\mathit{\alpha_{in}.G}`
.. |Hi|     replace:: :math:`\mathit{H_i}`
.. |aHi|    replace:: :math:`\mathit{\alpha_{in}.H_i}`
.. |Iin|    replace:: :math:`\mathit{I_{in}}`
.. |IIi|    replace:: :math:`\mathit{II_{in}}`
.. |Hupd|   replace:: :math:`\mathtt{H_{update}}`
.. |Hfin|   replace:: :math:`\mathtt{H_{finalize}}`
.. |lH|     replace:: :math:`\mathcal{L}`
.. |ctH|    replace:: :math:`\mathcal{C}`
.. |mlsagH| replace:: :math:`\mathcal{H}`
.. |ss|     replace:: :math:`\mathit{ss}`
.. |c|      replace:: :math:`\mathit{c}`
.. |DRVin|  replace:: :math:`\mathfrak{D}_\mathrm{in}`
.. |eDRVin| replace:: :math:`\widetilde{\mathfrak{D}_\mathrm{in}}`
.. |DRVout| replace:: :math:`\mathfrak{D}_\mathrm{out}`
.. |eDRVout| replace:: :math:`\widetilde{\mathfrak{D}_\mathrm{out}}`
.. |AKout|  replace::  :math:`\mathcal{AK}_\mathrm{amount}`
.. |eAKout| replace:: :math:`\widetilde{\mathcal{AK}_\mathrm{amount}}`

.. |idx|    replace:: :math:`\mathit{index}`
.. |H|      replace:: :math:`\mathtt{keccak}`
.. |enc|    replace:: :math:`\mathtt{AES}`
.. |dec|    replace:: :math:`\mathtt{AES^{-1}}`

.. |EPIT|   replace:: :math:`\mathtt{ENC\_PAYMENT\_ID\_TAIL}`

..
   ------------------------------------------------------------------------
                                 Doc Layout
   ------------------------------------------------------------------------

..
   ------------------------------------------------------------------------
                                Doc Content
   ------------------------------------------------------------------------

|_pb|

License
=======

Author: Cédric Mesnil <cslashm@gmail.com>

License:


  | Copyright 2017 Cédric Mesnil <cslashm@gmail.com>, Ledger SAS
  |
  | Licensed under the Apache License, Version 2.0 (the "License");
  | you may not use this file except in compliance with the License.
  | You may obtain a copy of the License at
  |
  |   http://www.apache.org/licenses/LICENSE-2.0
  |
  | Unless required by applicable law or agreed to in writing, software
  | distributed under the License is distributed on an "AS IS" BASIS,
  | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  | See the License for the specific language governing permissions and
  | limitations under the License.



|_pb|




Introduction
============

We want to enforce key protection, transaction confidentiality and transaction integrity against
potential malware on the Host. To achieve that we propose to use a Ledger NanoS as a 2nd
factor trusted device. Such a device has small amount of memory and is not capable of holding the entire transaction or building the required proofs in RAM. So we need to split the process between the
host and the NanoS. This draft note explain how.

Moreover this draft note also anticipates a future client feature and proposes a solution to integrate the
PR2056 for sub-address. This proposal is based on kenshi84 fork, branch sub-address-v2.

To summarize, the signature process is:

   . Generate a TX key pair |r.R|

   . Process Stealth Payment ID

   . For each input |Tin| to spend:

       - Compute the input public derivation data |DRVin|
       - Compute the spend key |xPin| from |Rin| and |bb|
       - Compute the key image |Iin| of |xin|

   . For each output |Tout| :

       - Compute the output secret derivation data |DRVout|
       - Compute the output public key |Pout|

   . For each output |Tout| :

       - compute the range proof
       - blind the amount

   . Compute the final confidential ring signature

   . Return TX


|_pb|

Notation
========


Elliptic curve points, such as pubic keys, are written in italic upper case,
and scalars, such as private keys, are written in italic lower case:


   - |spk| :             protection key

   - |r.R| :             transaction key pair

   - |a.A| |b.B| :       sender main view/spend key pair

   - |c.C| |d.D| :       sender sub view/spend key pair

   - |Aout| |Bout| :     receiver main view/spend public keys

   - |Cout| |Dout| :     receiver sub view/spend public key

   - |H| :               2nd group generator, such |Hf| and |h| is unknown

   - |v| :               amount to send/spent

   - |k| :               secret amount mask factor

   - |Ct| :              commitment to a with v such |Ctf|

   - |ai| :              secret co-signing key  for ith input

   - |xin| :             secret signing key for ith input

   - |Pin| :             public key of ith input

   - |Pout| :            public key of ith output

   - |DRVout| |DRVin| :  first level derivation data

Hash and encryption function:

   - |enc| :             [k](m) AES encryption of *m* with key *k*

   - |dec| :             [k](c) AES decryption of *c* with key *k*

Others:

   - |PayID| :           Stealth payment ID

   - |EPIT| :            0x82



|_pb|

State Machine
=============


**TBD**

Commands overview
=================

Introduction
------------

Hereafter are the code integration and application specification.

The commands are divided in three sets:

  - Provisioning
  - Low level crypto command
  - High level transaction command

  The low level set is a direct mapping of some crypto Monero function. For such command
  the Monero function will be referenced.

  The high level set encompasses functions that handle the confidential/sensitive part of
  full transaction

Common command format
---------------------

All command follow the generic ISO7816 command format, with the following meaning:

+------+--------+------------------------------------------+
| byte | length | description                              |
+======+========+==========================================+
| CLA  | 01     | Always zero '00'                         |
+------+--------+------------------------------------------+
| INS  | 01     | Command                                  |
+------+--------+------------------------------------------+
| P1   | 01     | Sub command                              |
+------+--------+------------------------------------------+
| P2   | 01     | Command/Sub command counter              |
+------+--------+------------------------------------------+
| LC   | 01     | byte length of `data`                    |
+------+--------+------------------------------------------+
| data | 01     | options                                  |
|      +--------+------------------------------------------+
|      | var    |                                          |
+------+--------+------------------------------------------+


When a command/sub-command can be sent repeatedly, the counter must be increased
by one at each command. The flag ``last sub command indicator`` must be set
to indicate another command will be sent.

*Common option encoding*

+---------------+----------------------------------------------------------+
| ``x--------`` | Last sub command indicator                               |
|               |                                                          |
| ``1--------`` | More identical subcommand forthcoming                    |
|               |                                                          |
| ``0--------`` | Last sub command                                         |
+---------------+----------------------------------------------------------+

|_pb|

Provisioning
============

Overview
--------

There is no provisioning in a standard setup. Both
key pairs |a.A| and |b.B| should be derived under BIP44 path.

The general BIP44 path is :

  ``/ purpose' / coin_type' / account' / change / address_index``


and is defined as follow for any Monero main address:

  `` /44'/128'/account'/0/0``

so in hexa:

  ``/0x8000002C/0x80000080/0x8......./0x00000000/0x00000000``

The *address_index* is set to *0* for the main address and will be used as
sub-address index according to kenshi84 fork.


In case an already existing key needs to be transferred, an optional dedicated
command may be provided. As there is no secure messaging for now, this
transfer shall be done from a trusted Host.
Moreover, as provisioning is not handled by Monero client, a separate tool must
be provided.


Commands
--------

Put keys
~~~~~~~~

**Description**

Put sender key pairs.

The application shall:

   | check  |A| ==  |aa|.|G|
   | check  |B| ==  |bb|.|G|
   | store |aa|, |A|, |bb|, |B|


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 32  | 00  | 00  | 80   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | |aa|                                                            |
+--------+-----------------------------------------------------------------+
| 20     | |A|                                                             |
+--------+-----------------------------------------------------------------+
| 20     | |bb|                                                            |
+--------+-----------------------------------------------------------------+
| 20     | |B|                                                             |
+--------+-----------------------------------------------------------------+
| 5f     | Base58 encoded public key                                       |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
|        |                                                                 |
+--------+-----------------------------------------------------------------+


Get Public Key
~~~~~~~~~~~~~~

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 30  | 01  | 00  | 80   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 5f     | Base58 encoded public key                                       |
+--------+-----------------------------------------------------------------+

Get Secret Keys
~~~~~~~~~~~~~~~

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 30  | 02  | 00  | 80   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | Encrypted view key                                              |
+--------+-----------------------------------------------------------------+
| 20     | Encrypted send key                                              |
+--------+-----------------------------------------------------------------+



|_pb|


Low level crypto commands
=========================


Overview
--------

TODO

Commands
--------

Derive Subaddress Public Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

    crypto_ops::derive_subaddress_public_key

**Description**

    | compute  |eDrv|  = |dec|[|spk|](|eDrv|)
    | compute  |s|  = |H|(|Drv| \| varint(|idx|))
    | compute  |s|  = |s| % |order|
    | compute  |P|' = |P| - |s|.|G|

return |P|'

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 46  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 32     | encrypted derivation key |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 04     | index |idx|                                                     |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | sub public key |P|'                                             |
+--------+-----------------------------------------------------------------+


Get Subaddress Spend Public Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

    get_subaddress_spend_public_key

**Description**

get_subaddress_secret_key:

    | compute  |s|  = |H|("SubAddr" \| |a| \| |idx| )
    | compute  |x|  = |s| % |order|

then:

    | compute  |D|  = |B| + |x|.|G|

return |D|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 4a  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 08     |  index (Major.minor) |idx|                                      |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | sub spend public key |D|                                        |
+--------+-----------------------------------------------------------------+

Get Subaddress
~~~~~~~~~~~~~~

**Monero**


**Description**

get_subaddress_secret_key:

    | compute  |s|  = |H|("SubAddr" \| |a| \| |idx| )
    | compute  |x|  = |s| % |order|

then:

    | compute  |D|  = |B| + |x|.|G|
    | compute  |C|  = |a|.|D|

return |C|, |D|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 48  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 08     | index (Major.minor) |idx|                                       |
+--------+-----------------------------------------------------------------+



**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | sub view public key |C|                                        |
+--------+-----------------------------------------------------------------+
| 32     | sub spend public key |D|                                       |
+--------+-----------------------------------------------------------------+

Get Subaddress Secret Key
~~~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

    get_subaddress_secret_key

**Description**

    | compute  |x|  =  |dec|[|spk|](|ex|)
    | compute  |s|  = |H|("SubAddr" \| |x| \| |idx| )
    | compute  |d|  = |s| % |order|
    | compute  |ed| = |dec|[|spk|](|d|)

return |ed|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 4c  | 00  | 00  | 39   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 08     | index (Major.minor) |idx|                                       |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | sub secret key |ed|                                            |
+--------+-----------------------------------------------------------------+

Verify Keys
~~~~~~~~~~~

**Monero**


**Description**


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 26  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 00     |                                                                 |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 00     |                                                                 |
+--------+-----------------------------------------------------------------+
| 00     |                                                                 |
+--------+-----------------------------------------------------------------+

Scalarmult Key
~~~~~~~~~~~~~~

**Monero**

rct::scalarmultKey

**Description**

    | compute |x| =  |dec|[|spk|](|ex|)
    | compute |xP| = |x|.|P|

return |xP|


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 42  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 32     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 00     | new public key |xP|                                             |
+--------+-----------------------------------------------------------------+


Scalarmult Base
~~~~~~~~~~~~~~~

**Monero**

rct::scalarmultBase


**Description**

    | compute |x| =  |dec|[|spk|](|ex|)
    | compute |xG| = |x|.|G|

return |xG|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 44  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+



**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 00     |                                                                 |
+--------+-----------------------------------------------------------------+
| 00     | new public key |xG|                                             |
+--------+-----------------------------------------------------------------+

Secret Add
~~~~~~~~~~

**Monero**



**Description**

    | compute |x1| = |dec|[|spk|](|ex1|)
    | compute |x1| = |dec|[|spk|](|ex1|)
    | compute |x|  = |x1| + |x2|
    | compute |ex| = |enc|[|spk|](|x|)

return |ex|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 3c  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | secret key |ex1|                                                |
+--------+-----------------------------------------------------------------+
| 32     | secret key |ex2|                                                |
+--------+-----------------------------------------------------------------+



**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+


Generate Keys
~~~~~~~~~~~~~

**Monero**


**Description**

    | generate |x|
    | compute  |xP| = |x|.|P|
    | compute  |ex| = |enc|[|spk|](|x|)

return |P|, |ex|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 40  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+



**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 00     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 00     | encrypted secret key |ex|                                       |
+--------+-----------------------------------------------------------------+

Generate Key Derivation
~~~~~~~~~~~~~~~~~~~~~~~

**Monero**


**Description**

 | compute  |x|    = |dec|[|spk|](|ex|)
 | compute  |D|    = |x|.|P|
 | compute  |Drv|  = 8.|D|
 | compute  |eDrv| = |enc|[|spk|](|Drv|)

return |eDrv|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 32  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 32     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+


Derivation To Scalar
~~~~~~~~~~~~~~~~~~~~

**Monero**

derivation_to_scalar

**Description**

    | compute  |Drv|  = |dec|[|spk|](|eDrv|)
    | compute  |s|    = |H|(|Drv| \| varint(|idx|))
    | compute  |s|    = |s| % |order|
    | compute  |es|   = |enc|[|spk|](|s|)

return |es|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 34  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 04     | index                                                           |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | encrypted scalar |es|                                           |
+--------+-----------------------------------------------------------------+


Derive Secret Key
~~~~~~~~~~~~~~~~~

**Monero**

derive_scecret_key

**Description**

    | compute  |eDrv| = |dec|[|spk|](|eDrv|)
    | compute  |x|    = |dec|[|spk|](|ex|)

derivation_to_scalar:

    | compute  |s|    = |H|(|Drv| \| varint(|idx|))
    | compute  |s|    = |s| % |order|

then:

    | compute  |x|'    = (|x|+|s|) % |order|
    | compute  |ex|'   = |enc|[|spk|](|x|)

return |ex|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 38  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 04     | index                                                           |
+--------+-----------------------------------------------------------------+
| 32     | encrypted secret key |ex|                                       |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | encrypted drevived secret key |ex|'                             |
+--------+-----------------------------------------------------------------+


Derive Public Key
~~~~~~~~~~~~~~~~~


**Monero**

derive_public_key

**Description**

    | compute  |eDrv| = |dec|[|spk|](|eDrv|)

derivation_to_scalar:

    | compute  |s|    = |H|(|Drv| \| varint(|idx|))
    | compute  |s|    = |s| % |order|

then:

    | compute  |P|'   = |P|+|s|.|G|

return |P|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 36  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 04     | index                                                           |
+--------+-----------------------------------------------------------------+
| 32     | encrypted secret key |P|                                        |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | public key |P|'                                                 |
+--------+-----------------------------------------------------------------+


Secret Key To Public Key
~~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

secret_key_to_public_key

**Description**

     | compute  |x| = |dec|[|spk|](|ex|)
     | compute  |P| = |x|.|G|

return |P|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 30  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | encrypted secret key |ex|                                       |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+


Generate Key Image
~~~~~~~~~~~~~~~~~~


**Monero**

generate_key_image

**Description**

     | compute  |x|   = |dec|[|spk|](|ex|)
     | compute  |s|   = |H|(|P|')
     | compute  |P|'  = ge_from_fe(|s|)
     | compute  |Img| = |x|.|P|'

return |Img|


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 3a  | 00  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 32     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 32     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 32     | key image  |Img|                                                 |
+--------+-----------------------------------------------------------------+


High Level Transaction command
==============================


Transaction process overview
----------------------------

The transaction is mainly generated in construct_tx_and_get_tx_key (or construct_tx) and construct_tx_with_tx_key
functions.

First, a new transaction keypai , |r.R| is generated.

Then, the stealth payment id is processed if any.

Then, for each input transaction to spend, the input key image is retrieved.

Then, for each output transaction, the destination key and the change address are computed.


Once |Tin| and |Tout| keys are set up, the genRCT/genRctSimple function is called.

First a commitment |Ct| to each |v| amount and its associated range proof are
computed to ensure the |v| amount confidentiality. The commitment and its range proof do not imply any secret and generate |Ct|, |k| such |Ctf|.

Then |k| and |v| are blinded by using the |AKout| which is only known in an encrypted form by the host.

After all commitments have been setup, the confidential ring signature happens.
This signature is performed by calling proveRctMG which then calls MLSAG_Gen.

At this point the amounts and destination keys must be validated on the NanoS. This
information is embedded in the message to sign by calling get_pre_mlsag_hash, prior to calling
ProveRctMG. So the get_pre_mlsag_hash
function will have to be modified to serialize the rv transaction to NanoS which
will validate the tuple <amount,dest> and compute the prehash.
The prehash will be kept inside NanoS to ensure its integrity.
Any further access to the prehash will be delegated.

Once the prehash is computed, the proveRctMG is called. This function only builds
some matrix and vectors to prepare the signature which is performed by the final
call MLSAG_Gen.

During this last step some ephemeral key pairs are generated : |ai|, |aGi|.
All |ai| must be kept secret to protect the x in keys.
Moreover we must avoid signing arbitrary values during the final loop.

In order to achieve this validation, we need to approve the original destination
address |Aout|, which is not recoverable from P out . Here the only solution is
to pass the original destination with the |k|, |v|. (Note this implies to add all
|Aout| in the rv structure).
So with |Aout|, we are able to recompute associated |Dout| (see step 3),
unblind |k| and |v| and then verify the commitment |Ctf|.
If |Ct| is verified and user validate |Aout| and |v|, |lH| is updated and we process
the next output.


Transaction Commands
--------------------


Open TX
~~~~~~~~


**Monero**

**Description**

Open a new transaction. Once open the device impose a certain order in subsequent commands:

  - OpenTX
  - Stealth
  - Blind \*
  - Initialize MLSAG-prehash
  - Update MLSAG-prehash \*
  - Finalize MLSAG-prehash
  - MLSAG prepare
  - MLSAG hash \*
  - MLSAG sign
  - CloseTX

During this sequence low level API remains available, but no other transaction can be started until the current one
is finished or aborted.


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 70  | 01  | cnt | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
+--------+-----------------------------------------------------------------+


Set Signature Mode
~~~~~~~~~~~~~~~~~~


**Monero**

**Description**

Set the signature to 'fake' or 'real'. In fake mode a random key is used to signed
the transaction and no user confirmation is requested.


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 72  | 01  | cnt | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 01     | 'fake' or 'real'                                                |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
+--------+-----------------------------------------------------------------+


Blind Amount and Mask
~~~~~~~~~~~~~~~~~~~~~~


**Monero**

**Description**

   | compute |AKout| = |dec|[|spk|](|eAKout|)
   | compute |ek|    = |k| + |H|(|AKout|)
   | compute |ev|    = |k| + |H|(|H|(|AKout|))
   | update |lH|     : |Hupd|(|v| \| |k| \| |AKout|)
   | if option 'last' is set:
   |   finalize |lH|

The application returns |ev|, |ek|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 7E  | 01  | cnt | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 20     | value |v|                                                       |
+--------+-----------------------------------------------------------------+
| 20     | mask |k|                                                        |
+--------+-----------------------------------------------------------------+
| 20    | encrypted private derivation data |eAKout|                       |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | blinded value |ev|                                              |
+--------+-----------------------------------------------------------------+
| 20     | blinded mask |ek|                                               |
+--------+-----------------------------------------------------------------+


Pre Hash
~~~~~~~~


Initialize MLSAG-prehash
^^^^^^^^^^^^^^^^^^^^^^^^


**Description**

During the first step, the application updates the |mlsagH|  with the transaction
header:

   | Initialize |ctH|
   | Initialize |lH|'
   | Initialize |mlsagH| : |Hupd|(:math:`header`)


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 82  | 01  | cnt  | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

 if ``cnt==1`` :

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 01     | type                                                            |
+--------+-----------------------------------------------------------------+
| varint | txnFee                                                          |
+--------+-----------------------------------------------------------------+

if ``cnt>1`` :

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | pseudoOut                                                       |
+--------+-----------------------------------------------------------------+


Update MLSAG-prehash
^^^^^^^^^^^^^^^^^^^^


**Description**

On the second step the application receives amount and destination and check
values. It also re-compute the |lH| value to ensure consistency with steps 3 and 4.
So for each command received, do:

   | compute |Drv| =  8.|rr|.|Aout|
   | compute |k|   = |ek| - |H|(|Drv|)
   | compute |v|   = |ek| - |H|(|H|(|Drv|))
   | check |Ctf|

   | ask user validation of |Aout|, |Bout|
   | ask user validation of |v|

   | update |ctH| : |Hupd|(|Ct|)
   | update |lH|' : |Hupd|(|v| \| |k| \| |Drv|)

   | update |mlsagH| : |Hupd|(:math:`ecdhInfo`)

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 82  | 02  | cnt | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 01     | 1 if sub-address, 0 else                                        |
+--------+-----------------------------------------------------------------+
| 20     | Real destination view key |Aout|                                |
+--------+-----------------------------------------------------------------+
| 20     | Real destination spend key |Bout|                               |
+--------+-----------------------------------------------------------------+
| 20     | |Ct| of |v|,|k|                                                 |
+--------+-----------------------------------------------------------------+
| 40     | one serialized ecdhInfo :                                       |
|        |                                                                 |
|        | | {                                                             |
|        | |    bytes[32] mask   (|ek|)                                    |
|        | |    bytes[32] amount (|ev|)                                    |
|        | | }                                                             |
|        |                                                                 |
+--------+-----------------------------------------------------------------+


Finalize MLSAG-prehash
^^^^^^^^^^^^^^^^^^^^^^


**Description**

Finally the application receives the last part of data:

   | finalize |lH|' : |Hfin|()
   | check |lH| == |lH|'

   | finalize |ctH| : |Hfin|()
   | compute |ctH|' = |Hfin|(:math:`commitment_0.Ct  | commitment_1.Ct | .....`)                                                           |
   | check |ctH| == |ctH|'

   | finalize |mlsagH| : |Hfin|(:math:`commitments`)
   | compute |mlsagH| = |H|(:math:`message` \| |mlsagH| \| :math:`proof`)


Keep |mlsagH|

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 82  | 03  | 00  | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

not last:

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |

+--------+-----------------------------------------------------------------+
| 20     | one serialized commitment :                                     |
|        |                                                                 |
|        | | {                                                             |
|        | |    bytes[32] mask   (|Ct|)                                    |
|        | | }                                                             |
|        |                                                                 |
+--------+-----------------------------------------------------------------+

last:

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 20     | message (rctSig.message)                                        |
+--------+-----------------------------------------------------------------+
| 20     | proof (proof range hash)                                        |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
|        |                                                                 |
+--------+-----------------------------------------------------------------+


MLSAG
~~~~~

MLSAG prepare
^^^^^^^^^^^^^


**Description**

Generate the matrix ring parameters:

   | generate |ai| ,
   | compute |aGi|
   | if real key:
   |     check the order of |Hi|
   |     compute |xin| =  |dec|[|spk|](|exin|)
   |     compute |IIi| = |xin|.|Hi|
   |     compute |aHi|
   |     compute |eai| = |enc|[|spk|](|ai|)

return |eai| , |aGi| [ |aHi|, |IIi|]


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 84  | 01  | cnt | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

for real key:

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 20     | point                                                           |
+--------+-----------------------------------------------------------------+
| 20     | secret spend key |exin|                                         |
+--------+-----------------------------------------------------------------+


for random ring key

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+


**Response data**

for real key:

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | |aHi|                                                           |
+--------+-----------------------------------------------------------------+
| 20     | |aGi|                                                           |
+--------+-----------------------------------------------------------------+
| 20     | |IIi|                                                           |
+--------+-----------------------------------------------------------------+
| 20     | encrypted |ai| : |eai|                                          |
+--------+-----------------------------------------------------------------+

for random ring key

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | |aHi|                                                           |
+--------+-----------------------------------------------------------------+
| 20     | |aGi|                                                           |
+--------+-----------------------------------------------------------------+


MLSAG hash
^^^^^^^^^^^

**Description**

Compute the last matrix ring parameter:

   | replace the first 32 bytes of ``inputs`` by the previously computed MLSAG-prehash
   | compute c = |H|(``inputs``)


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 84  | 02  | 00  | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| var    | inputs                                                          |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
|        |                                                                 |
+--------+-----------------------------------------------------------------+


MLSAG sign
^^^^^^^^^^

**Description**

Finally compute all signatures:

    | compute |ai|  = |dec|[|spk|](|eai|)
    | compute |xin| = |dec|[|spk|](|exin|)
    | compute |ss|  = (|ai| - |c| * |xin| ) % |l|

return |ss|


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 84  | 03  | cnt | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 20     | |exin|                                                          |
+--------+-----------------------------------------------------------------+
| 20     | |eai|                                                           |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | signature |ss|                                                  |
+--------+-----------------------------------------------------------------+



Conclusion
==========

This draft note explains how to protect Monero transactions of the official client with a NanoS.
According to the latest SDK, the necessary RAM for global data is evaluated to around 0.8 Kilobytes
for a transaction with one output and 1,7 Kilobytes for a transaction with ten outputs.
The proposed NanoS interaction should be enhanced with a strong state machine to avoid multiple
requests for the same data and limit any potential cryptanalysis.

References
----------

   | [1] `<https://github.com/monero-project/monero/tree/v0.10.3.1>`_
   | [2] `<https://github.com/monero-project/monero/pull/2056>`_
   | [3] `<https://github.com/kenshi84/monero/tree/subaddress-v2>`_
   | [4] `<https://www.reddit.com/r/Monero/comments/6invis/ledger_hardware_wallet_monero_integration>`_
   | [5] `<https://github.com/moneroexamples>`_

