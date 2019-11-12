
..
   Copyright 2017-2019 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS <cedric@ledger.fr>
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
.. |x1|     replace:: :math:`\mathit{x_1}`
.. |ex1|    replace:: :math:`\widetilde{\mathit{x_1}}`
.. |x2|     replace:: :math:`\mathit{x_2}`
.. |ex2|    replace:: :math:`\widetilde{\mathit{x_2}}`
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
.. |er|     replace:: :math:`\widetilde{\mathit{r}}`
.. |r.R|    replace:: :math:`(\mathit{r, R})`

.. |PayID|  replace:: :math:`\mathit{PayID}`
.. |ePayID| replace:: :math:`\widetilde{\mathit{PayID}}`
.. |H|      replace:: :math:`\mathit{H}`
.. |h|      replace:: :math:`\mathit{h}`
.. |Hf|     replace:: :math:`\mathit{H = h.G}`
.. |l|      replace:: :math:`\mathit{l}`
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
.. |mlsagH| replace:: :math:`\mathcal{H}`
.. |ss|     replace:: :math:`\mathit{ss}`
.. |c|      replace:: :math:`\mathit{c}`
.. |DRVin|  replace:: :math:`\mathfrak{D}_\mathrm{in}`
.. |eDRVin| replace:: :math:`\widetilde{\mathfrak{D}_\mathrm{in}}`
.. |DRVout| replace:: :math:`\mathfrak{D}_\mathrm{out}`
.. |eDRVout| replace:: :math:`\widetilde{\mathfrak{D}_\mathrm{out}}`
.. |AKout|  replace::  :math:`\mathcal{AK}_\mathrm{amount}`
.. |eAKout| replace:: :math:`\widetilde{\mathcal{AK}_\mathrm{amount}}`


.. |ctH|       replace:: :math:`\mathcal{H}_\mathrm{commitment}`
.. |outKeysH|  replace:: :math:`\mathcal{H}_\mathrm{outkeys}`

.. |v|      replace:: :math:`\mathcal{\mathrm{amount}}`
.. |ev|     replace:: :math:`\widetilde{\mathcal{\mathrm{amount}}}`
.. |k|      replace:: :math:`\mathcal{\mathrm{mask}}`
.. |ek|     replace:: :math:`\widetilde{\mathcal{\mathrm{mask}}}`
.. |Ct|     replace:: :math:`\mathit{C_v}`
.. |Ctf|    replace:: :math:`\mathit{C_v = k.G + v.H}`

.. |idx|    replace:: :math:`\mathit{index}`
.. |enc|    replace:: :math:`\mathtt{AES}`
.. |dec|    replace:: :math:`\mathtt{AES^{-1}}`

.. |Hupd|   replace:: :math:`\mathtt{H_{update}}`
.. |Hfin|   replace:: :math:`\mathtt{H_{finalize}}`


.. |Hs|      replace:: :math:`\mathtt{HashToScalar}`
.. |Hps|     replace:: :math:`\mathtt{HashPointToScalar}`
.. |Hp|      replace:: :math:`\mathtt{HashToPoint}`
.. |keyDrv|  replace:: :math:`\mathtt{KeyDerivation}`

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


  | Copyright 2017-2019 Cédric Mesnil <cslashm@gmail.com>, Ledger SAS
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
potential malware on the Host. To achieve that we propose to use a Ledger Nano S/X as a 2nd
factor trusted device. Such a device has small amount of memory and is not capable of holding the entire transaction or building the required proofs in RAM. So we need to split the process between the
host and the NanoS. This draft note explain how.

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

   - |v| :               amount to send/spend

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
| CLA  | 01     | Protocol version                         |
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
|      |        |                                          |
|      | var    | additional data                          |
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

Provisioning And Key Management
================================

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

Reset
~~~~~

**Description**

Restart the application and check client/application versions compatibility.


**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 02  | 00  | 00  | ll   |
+-----+-----+-----+-----+------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| var    | string version, without trailing null byte                      |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | Application major version                                       |
+--------+-----------------------------------------------------------------+
| 01     | Application minor version                                       |
+--------+-----------------------------------------------------------------+
| 01     | Application micro version                                       |
+--------+-----------------------------------------------------------------+


Put keys
~~~~~~~~

**Description**

Put sender key pairs.

This command allows to set specific key on the device and should only be used for testing purpose.

The application shall:

   | check  |A| ==  |aa|.|G|
   | check  |B| ==  |bb|.|G|
   | store |aa|, |A|, |bb|, |B|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 22  | 00  | 00  | e0   |
+-----+-----+-----+-----+------+

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

**Description**

Retrieves public base58 encoded public key.

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 20  | 01  | 00  | 01   |
+-----+-----+-----+-----+------+

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
| 20     | "A" view public key                                             |
+--------+-----------------------------------------------------------------+
| 20     | "B" view spend key                                              |
+--------+-----------------------------------------------------------------+
| 5f     | Base58 encoded public key                                       |
+--------+-----------------------------------------------------------------+

Get Private View Keys
~~~~~~~~~~~~~~~~~~~~~

**Description**

Retrieves the private view key in order to accelarate the blockchain scan.

The device should ask the user to accept or reject this export. If rejected
the client will use the device for scanning the blockchain.

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 20  | 02  | 00  | 01   |
+-----+-----+-----+-----+------+


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
| 20     | "a" secret view key                                             |
+--------+-----------------------------------------------------------------+


Display Address
~~~~~~~~~~~~~~~

**Monero**


**Description**

Display requested main address ,sub address or integrated adrdess.


    | compute |x| =  |dec|[|spk|](|ex|)

if payment ID is provided:

    | compute |xP| = |x|.|G|
    | check   |xP| == |P|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 21  | xx  | 00  | 11   |
+-----+-----+-----+-----+------+

if P1 is '00' display non-integradted address.

if P1 is '01' display integrated address.

Any other value will be rejected.

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 08     |  index (Major.minor) |idx|                                      |
+--------+-----------------------------------------------------------------+
| 08     |  Payment ID, (or '0000000000000000')                            |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
|        |                                                                 |
+--------+-----------------------------------------------------------------+


|_pb|


Low level crypto commands
=========================


Overview
--------

This section describe lowlevel commands that can be used in a transaction or not.


Commands
--------


Verify Keys
~~~~~~~~~~~

**Monero**

device_default::verify_keys.

**Description**

Verify that the provided private key and public key match.


    | compute |x| =  |dec|[|spk|](|ex|)
    | compute |xP| = |x|.|G|
    | check   |xP| == |P|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 26  | xx  | 00  | 41   |
+-----+-----+-----+-----+------+

if P1 is '00' the provided public key will be used.

if P1 is '01' the public view is key will be used and the provided public key will
be 'ignored'

if P is '02' the public spend is key will be used and the provided public key will
be 'ignored'

Any other value will be rejected.

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     |  secret key |ex|                                                |
+--------+-----------------------------------------------------------------+
| 20     |  public key or '00'\*32      |P|                                |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
|        |                                                                 |
+--------+-----------------------------------------------------------------+


Get ChaCha8 PreKey
~~~~~~~~~~~~~~~~~~~

**Monero**


**Description**

    | compute  |s|  = |H|(|a| \| |b| \| |EPIT|)

return the full internal state (200 bytes) of Keccak.

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 24  | 00  | 00  | 00   |
+-----+-----+-----+-----+------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
|        |                                                                 |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| C8     | ChaCha8 prekey                                                  |
+--------+-----------------------------------------------------------------+


Generate Key Derivation
~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

crypto::generate_key_derivation.

**Description**

Compute the secret key derivation and returned it encrypted.

 | compute  |x|    = |dec|[|spk|](|ex|)
 | compute  |Drv|  = |keyDrv|(|x|,|P|)
 | compute  |eDrv| = |enc|[|spk|](|Drv|)

return |eDrv|.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 32  | 00  | 00  | 41 or 61 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+


Derivation To Scalar
~~~~~~~~~~~~~~~~~~~~

**Monero**

crypto::derivation_to_scalar.

**Description**

Transform a secret derivation data to a secret scalar according to its index.

    | compute  |Drv|  = |dec|[|spk|](|eDrv|)
    | compute  |s|    = |Hps|(|Drv|, |idx|)
    | compute  |es|   = |enc|[|spk|](|s|)

return |es|.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 34  | 00  | 00  | 25 or 45 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 04     | index                                                           |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | encrypted scalar |es|                                           |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+


Derive Public Key
~~~~~~~~~~~~~~~~~

**Monero**

crypto::derive_public_key.

**Description**

Compute a new public key from some secret derivation data, a parent public key and its index.

    | compute  |eDrv| = |dec|[|spk|](|eDrv|)

derivation_to_scalar:

    | compute  |s|    = |Hps|(|Drv|, |idx|)

then:

    | compute  |P|'   = |P|+|s|.|G|

return |P|'.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 36  | 00  | 00  | 25 or 45 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 04     | index                                                           |
+--------+-----------------------------------------------------------------+
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | public key |P|'                                                 |
+--------+-----------------------------------------------------------------+


Derive Secret Key
~~~~~~~~~~~~~~~~~

**Monero**

crypto::derive_secret_key.

**Description**

Compute a new secret key from some secret derivation data, a parent secret key and its index.

    | compute  |eDrv| = |dec|[|spk|](|eDrv|)
    | compute  |x|    = |dec|[|spk|](|ex|)

derivation_to_scalar:

    | compute  |s|    = |Hps|(|Drv|, |idx|)

then:

    | compute  |x|'    = (|x|+|s|) % |order|
    | compute  |ex|'   = |enc|[|spk|](|x|)

return |ex|.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 38  | 00  | 00  | 65 or 85 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | encrypted key derivation |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 04     | index                                                           |
+--------+-----------------------------------------------------------------+
| 20     | encrypted secret key |ex|                                       |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | encrypted derived secret key |ex|'                              |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+


Derive Subaddress Public Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

crypto_ops::derive_subaddress_public_key.

**Description**

    | compute  |eDrv|  = |dec|[|spk|](|eDrv|)
    | compute  |s|  = |Hps|(|Drv|, |idx|)
    | compute  |P|' = |P| - |s|.|G|

return |P|'

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 46  | 00  | 00  | 45 or 65 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 20     | encrypted derivation key |eDrv|                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 04     | index |idx|                                                     |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | sub public key |P|'                                             |
+--------+-----------------------------------------------------------------+


Get Subaddress Spend Public Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

device_default::get_subaddress_spend_public_key.

**Description**

get_subaddress_secret_key:

    | compute  |s|  = |H|("SubAddr" \| |a| \| |idx| )
    | compute  |x|  = |s| % |order|

then:

    | compute  |D|  = |B| + |x|.|G|

return |D|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 4a  | 00  | 00  | 09   |
+-----+-----+-----+-----+------+

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
| 20     | sub spend public key |D|                                        |
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

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 4c  | 00  | 00  | 39 or 59 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 08     | index (Major.minor) |idx|                                       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | sub secret key |ed|                                             |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+


Get Subaddress
~~~~~~~~~~~~~~

**Monero**

device_default::get_subaddress_secret_key.

**Description**



    | compute  |s|  = |H|("SubAddr" \| |a| \| |idx| )
    | compute  |x|  = |s| % |order|

then:

    | compute  |D|  = |B| + |x|.|G|
    | compute  |C|  = |a|.|D|

return |C|, |D|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 48  | 00  | 00  | 09   |
+-----+-----+-----+-----+------+

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
| 20     | sub view public key |C|                                        |
+--------+-----------------------------------------------------------------+
| 20     | sub spend public key |D|                                       |
+--------+-----------------------------------------------------------------+



Generate Key Image
~~~~~~~~~~~~~~~~~~

**Monero**

crypto::generate_key_image.

**Description**

Compute the key image of a key pair.

     | compute  |x|   = |dec|[|spk|](|ex|)
     | compute  |P|'  = |Hp|(|P|)
     | compute  |Img| = |x|.|P|'

return |Img|.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 3a  | 00  | 00  | 41 or 61 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | key image  |Img|                                                |
+--------+-----------------------------------------------------------------+


Generate Keypair
~~~~~~~~~~~~~~~~

**Monero**

crypto::generate_keys.

**Description**

Generate a new keypair and return it. The secret key is returned encrypted.

    | generate |x|
    | compute  |xP| = |x|.|P|
    | compute  |ex| = |enc|[|spk|](|x|)

return |P|, |ex|.

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 40  | 00  | 00  | 01   |
+-----+-----+-----+-----+------+

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
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 20     | encrypted secret key |ex|                                       |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+




Secret Key To Public Key
~~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

crypto::secret_key_to_public_key.

**Description**

Compute a public key from secret a secret key.

     | compute  |x| = |dec|[|spk|](|ex|)
     | compute  |P| = |x|.|G|

return |P|.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 30  | 00  | 00  | 21 or 41 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | encrypted secret key |ex|                                       |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+


Secret Add
~~~~~~~~~~

**Monero**

sc_add

**Description**

    | compute |x1| = |dec|[|spk|](|ex1|)
    | compute |x2| = |dec|[|spk|](|ex2|)
    | compute |x|  = |x1| + |x2|
    | compute |ex| = |enc|[|spk|](|x|)

return |ex|.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 3c  | 00  | 00  | 41 or 61 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex1|                                                |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex2|                                                |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+


Secret Sub
~~~~~~~~~~

**Monero**

sc_sub

**Description**

    | compute |x1| = |dec|[|spk|](|ex1|)
    | compute |x1| = |dec|[|spk|](|ex1|)
    | compute |x|  = |x1| - |x2|
    | compute |ex| = |enc|[|spk|](|x|)

return |ex|.

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 3E  | 00  | 00  | 41 or 61 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex1|                                                |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex2|                                                |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+


Secret Scalar Mult Key
~~~~~~~~~~~~~~~~~~~~~~

**Monero**

rct::scalarmultKey.

**Description**

Multiply a secret scalar with a public key.

    | compute |x| =  |dec|[|spk|](|ex|)
    | compute |xP| = |x|.|P|

return |xP|


**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 42  | 00  | 00  | 41 or 61 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | new public key |xP|                                             |
+--------+-----------------------------------------------------------------+


Secret Scalar Mult Base
~~~~~~~~~~~~~~~~~~~~~~~

**Monero**

rct::scalarmultBase.

**Description**

Multiply a secret scalar with the publis base point |G|.

    | compute |x| =  |dec|[|spk|](|ex|)
    | compute |xG| = |x|.|G|

return |xG|

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 44  | 00  | 00  | 21 or 41 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | secret key |ex|                                                 |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 00     |                                                                 |
+--------+-----------------------------------------------------------------+
| 20     | new public key |xG|                                             |
+--------+-----------------------------------------------------------------+



Stealth
~~~~~~~

**Monero**



**Description**

Encrypt payment ID

    | compute |x| =  |dec|[|spk|](|ex|)
    | compute |Drv| = |keyDrv|(|P|, |x|)
    | compute |s| = |Hs|( |DRV| \| |EPIT|)
    | compute |PayID| = |ePayID|^|s|

return |PayID|

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 44  | 00  | 00  | 61 or 81 |
+-----+-----+-----+-----+----------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | public key |P|                                                  |
+--------+-----------------------------------------------------------------+
| 20     | encryped secret key |ex|                                        |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 20     | encryped payment ID |ePayID|                                    |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | payment ID |PayID|                                             |
+--------+-----------------------------------------------------------------+


Unblind
~~~~~~~~

**Monero**


**Description**

Unblind amount and his mask.

First:

   | compute |AKout| =  |dec|[|spk|](|eAKout|)

If blind V1:

    | compute |s| =  |Hs|(|AKout|)
    | compute |ek| = |k|-|s|
    | compute |s| =  |Hs|(|a|)
    | compute |ev| = |v|-|s|

If blind V2:
    | compute |k| = |Hs|("commitment_mask" \| |Akout|) % order
    | compute |s| = |Hs|("amount" \|  |Akout|)
    | compute |v|[0:7] = |ev|[0:7]^|s|[0:7]

return |ek|,|ev|

**Command**

+-----+-----+-----+-----+----------+
| CLA | INS | P1  | P2  | LC       |
+=====+=====+=====+=====+==========+
| 02  | 44  | 00  | 00  | 61 or 81 |
+-----+-----+-----+-----+----------+


*specific options*

+---------------+----------------------------------------------------------+
| ``-------xx`` | Commitment scheme version                                |
|               |                                                          |
| ``-------10`` | Blind V2                                                 |
|               |                                                          |
| ``-------00`` | Blind V1                                                 |
+---------------+----------------------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | xx                                                              |
+--------+-----------------------------------------------------------------+
| 20     | encryped blinding factor |AKout|                                |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac (optional, only during active transaction)       |
+--------+-----------------------------------------------------------------+
| 20     | blinded mask |ek|                                               |
+--------+-----------------------------------------------------------------+
| 20     | blinded amount |ev|                                             |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | mask |ek|                                                       |
+--------+-----------------------------------------------------------------+
| 20     | amount |ev|                                                     |
+--------+-----------------------------------------------------------------+



High Level Transaction command
==============================


Transaction process overview
----------------------------

The transaction is mainly generated in construct_tx_and_get_tx_key (or construct_tx) and
construct_tx_with_tx_key
functions.

First, a new transaction keypair |r.R| is generated.

Then, the stealth payment id is processed if any.

Then, for each input transaction to spend, the input key image is retrieved.

Then, for each output transaction, the epehemeral destination key and the blinding key
amount |AKout| are computed.


Once |Tin| and |Tout| keys are set up, the genRCT/genRctSimple function is called.

First a commitment |Ct| to each |v| amount and its associated range proof are
computed to ensure the |v| amount confidentiality. The commitment and its range proof
do not imply any secret and generate |Ct|, |k| such |Ctf|.

Then |k| and |v| are blinded by using the |AKout| which is only known in an encrypted
form by the host.

After all commitments have been setup, the confidential ring signature happens.
This signature is performed by calling proveRctMG which then calls MLSAG_Gen.

At this point the amounts and destination keys must be validated on the NanoS. This
information is embedded in the message to sign by calling get_pre_mlsag_hash, prior
to calling ProveRctMG. So the get_pre_mlsag_hash function will have to be modified to
serialize the rv transaction to NanoS which will validate the tuple <amount,dest> and
compute the prehash.
The prehash will be kept inside NanoS to ensure its integrity.
Any further access to the prehash will be delegated.

Once the prehash is computed, the proveRctMG is called. This function only builds
some matrix and vectors to prepare the signature which is performed by the final
call MLSAG_Gen.

During this last step some ephemeral key pairs are generated : |ai|, |aGi|.
All |ai| must be kept secret to protect the |xin| keys.
Moreover we must avoid signing arbitrary values during the final loop.

In order to achieve this validation, we need to approve the original destination
address |Aout||Bout|, which is not recoverable from P out . Here the only solution is
to pass the original destination with the |k|, |v|, |AKout|.

Unblind |k| and |v| and then verify the commitment |Ctf|.
If |Ct| is verified and user validate |Aout|,|Bout| and |v|, continue.


Transaction Commands
--------------------


Open TX
~~~~~~~~

**Description**

Open a new transaction. Once open the device impose a certain order in subsequent commands:

  - OpenTX
  - Stealth
  - Get TX output keys
  - Blind \*
  - Initialize MLSAG-prehash
  - Update MLSAG-prehash \*
  - Finalize MLSAG-prehash
  - MLSAG prepare
  - MLSAG hash \*
  - MLSAG sign
  - CloseTX

During this sequence low level API remains available, but no other transaction can be started until the current one is finished or aborted.

   | Initialize |outKeysH|
   | compute initial transaction key pair |r.R|

return |r.R|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 70  | 01  | cnt | 05   |
+-----+-----+-----+-----+------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 04     | account identifier (ignored, RFU)                               |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | public transcation key |R|                                      |
+--------+-----------------------------------------------------------------+
| 20     | encrypted private transaction key |er|                          |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac of view key                                      |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac of spend key                                     |
+--------+-----------------------------------------------------------------+


Set Signature Mode
~~~~~~~~~~~~~~~~~~

**Description**

Set the signature to 'fake' or 'real'. In fake mode a random key is used to signed
the transaction and no user confirmation is requested.


**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 72  | 00  | 00  | 02   |
+-----+-----+-----+-----+------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 01     | '1' aka 'fake' or '2' aka real'                                 |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
|        |                                                                 |
+--------+-----------------------------------------------------------------+



Generate Commitment Mask
~~~~~~~~~~~~~~~~~~~~~~~~

**Description**

| compute |s| = |Hs|("commitment_mask" \| |AKout|)

Return |s|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 77  | 00  | 00  | 21   |
+-----+-----+-----+-----+------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | 00                                                              |
+--------+-----------------------------------------------------------------+
| 20     | encryped blinding factor |AKout|                                |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | commitment mask |s|                                             |
+--------+-----------------------------------------------------------------+


Blind
~~~~~

**Monero**


**Description**

Blind amount and his mask.

First:

   | compute |AKout| =  |dec|[|spk|](|eAKout|)

If blind V1:

    | compute |s| =  |Hs|(|AKout|)
    | compute |ek| = |k|+|s|
    | compute |s| =  |Hs|(|a|)
    | compute |ev| = |v|+|s|

If blind V2:

    | set |ek| to 32 zero bytes
    | compute |s| = |Hs|("amount" \| |AKout|)
    | compute |ev| = |v|[0:7]^|s|[0:7]

return |ek|,|ev|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 78  | 00  | 00  | 81   |
+-----+-----+-----+-----+------+

*specific options*

+---------------+----------------------------------------------------------+
| ``-------xx`` | Commitment scheme version                                |
|               |                                                          |
| ``-------10`` | Blind V2                                                 |
|               |                                                          |
| ``-------00`` | Blind V1                                                 |
+---------------+----------------------------------------------------------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | xx                                                              |
+--------+-----------------------------------------------------------------+
| 20     | encryped blinding factor |AKout|                                |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+
| 20     | mask |k|                                                        |
+--------+-----------------------------------------------------------------+
| 20     | amount |v|                                                      |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | blinded  mask |ek|                                              |
+--------+-----------------------------------------------------------------+
| 20     | blinded amount |ev|                                             |
+--------+-----------------------------------------------------------------+


Generate TX output keys
~~~~~~~~~~~~~~~~~~~~~~~

**Description**

.. |nak|      replace:: :math:`\mathit{need\_additional\_key}`
.. |ak|       replace:: :math:`\mathit{additional\_key}`
.. |txsec|    replace:: :math:`\mathit{tx_{sec}}`
.. |sub|      replace:: :math:`\mathit{is\_subaddress}`
.. |chgaddr|  replace:: :math:`\mathit{is\_change\_address}`

Compute addtional key |P| if needed,  amount key blinding and ephemeral destination key.

   | if |nak| :
   |     if |sub| :
   |         compute |R|' = |ak|.|Bout|
   |     else
   |         compute |R|' = |ak|.|G|
   |
   | if |chgaddr| :
   |     compute |Drv| = |keyDrv|(|a|,|R|)
   | else
   |     if |nak| and |sub|:
   |         compute |Drv| = |keyDrv|(|ak|,|Aout|)|
   |     else:
   |         compute |Drv| = |keyDrv|(|r|,|Aout|)
   |
   | compute |AKout|  = |Hps|(|Drv|,|idx|)
   | compute |eAKout| = |enc|[|spk|](|AKout|)
   |
   | compute  |s| = |Hps|(|Drv|,|idx|)
   | compute  |P| = |Bout|+|s|.|G|
   |
   | update |outKeysH| : |Hupd|(|Aout|,|Bout|,is_change,|AKout|)
   | if option 'last' is set:
   |   finalize |outKeysH|

The application returns

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 7B  | 01  | cnt | EC   |
+-----+-----+-----+-----+------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 04     | tx version                                                      |
+--------+-----------------------------------------------------------------+
| 20     | secret tx key |r|                                               |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+
| 20     | public tx key |R|                                               |
+--------+-----------------------------------------------------------------+
| 20     | destination public view key |Aout|                              |
+--------+-----------------------------------------------------------------+
| 20     | destination public spend key |Bout|                             |
+--------+-----------------------------------------------------------------+
| 04     | output index  |idx|                                             |
+--------+-----------------------------------------------------------------+
| 01     | is change address                                               |
+--------+-----------------------------------------------------------------+
| 01     | is subaddress                                                   |
+--------+-----------------------------------------------------------------+
| 01     | need additional key |nak|:  1 if yes, 0 else                     |
+--------+-----------------------------------------------------------------+
| 20     | encrypted additional key |ak|, if |nak| == 1, 0\*32 else        |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | encrypted amouny key blinding |eAKout|                          |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral destination key |P|                                   |
+--------+-----------------------------------------------------------------+
| 20     | additional Key |R|' if |nak| == 1, not present else              |
+--------+-----------------------------------------------------------------+


Validate and Pre Hash
~~~~~~~~~~~~~~~~~~~~~

Initialize MLSAG-prehash
^^^^^^^^^^^^^^^^^^^^^^^^

**Description**

During the first step, the application updates the |mlsagH|  with the transaction
header:

if cnt == 1

   | Finalize |outKeysH|
   | Initialize |outKeysH|'
   | Initialize |ctH|
   | Initialize |mlsagH|
   | update |mlsagH| : |Hupd|(:math:`txnFee`)
   | request user to validate :math:`txnFee`

else

   | update |mlsagH| : |Hupd|(:math:`pseudoOut`)


**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 7C  | 01  | cnt  | var |                                           |
+-----+-----+-----+-----+------+


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
values. It also re-compute the |outKeysH| value to ensure consistency with steps 3 and 4.
So for each command received, do:

   | compute |Akout| =   |dec|[|spk|](|eAKout|)
   |
   | update |outKeysH|'' : |Hupd|(|Aout| \| |Bout| \| is_change \| |AKout|)
   |
   | if blind v1
   |   compute |k|   = |ek| - |Hs|(|Akout|)
   |   compute |v|   = |ev| - |Hs|(|Hs|(|Akout|))
   |
   | if blind v2
   |   compute |k|   = |Hs|("commitment_mask"||Akout|)) % |order|
   |   compute |s|   = |Hs|("amount"|||Akout|)
   |   compute |v|[0:7]   = |ev|[0:7] ^ |s|[0:7]
   |
   | check |Ct| == |k|.|G| + |v|.|H|   |
   | update |ctH| : |Hupd|(|Ct|)
   |
   | if last command:
   |   finalize |outKeysH|'
   |   check |outKeysH|' == |outKeysH|
   |   finalize |ctH|
   |
   |
   | update |mlsagH| : |Hupd|(:math:`ecdhInfo`)
   |
   | ask user validation of |Aout|, |Bout|, |v|
   |


**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 7C  | 02  | cnt | E3   |
+-----+-----+-----+-----+------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 01     | 1 if sub-address, 0 else                                        |
+--------+-----------------------------------------------------------------+
| 01     | 1 if change-address, 0 else                                     |
+--------+-----------------------------------------------------------------+
| 20     | Real destination public view key |Aout|                         |
+--------+-----------------------------------------------------------------+
| 20     | Real destination public spend key |Bout|                        |
+--------+-----------------------------------------------------------------+
| 20     | encrypted amount key blinding |eAKout|                          |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
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

*specific options*

+---------------+----------------------------------------------------------+
| ``-------xx`` | Mask scheme version                                      |
|               |                                                          |
| ``-------10`` | Blind V2                                                 |
|               |                                                          |
| ``-------00`` | Blind V1                                                 |
+---------------+----------------------------------------------------------+

Note: Whatever the mask scheme is, |v| is always transmited as 32 bytes.


Finalize MLSAG-prehash
^^^^^^^^^^^^^^^^^^^^^^


**Description**

Finally the application receives the last part of data:

   | if cnt == 1
   |   Initialize |ctH|'
   |
   | if last command:
   |   finalize |ctH|'
   |   check |ctH| == |ctH|'
   |   update |mlsagH|:
   |   |s| = finalize |mlsagH|
   |   compute |mlsagH| = |Hs| (:math:`message` \| |s|  \| :math:`proof`)
   |
   | else
   |   update |ctH|': |Hupd|(|Ct|)
   |   update |mlsagH|: |Hupd|(|Ct|)


Keep |mlsagH|

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 7C  | 03  | cnt | 21   |
+-----+-----+-----+-----+------+


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
   |     compute |aHi|
   |     compute |eai| = |enc|[|spk|](|ai|)
   |     if not option\_clear\_xin:
   |         compute |xin| =  |dec|[|spk|](|exin|)
   |     compute |IIi| = |xin|.|Hi|
   |
   |
   |

return |eai| , |aGi| [|aHi|, |IIi|]


**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 84  | 01  | cnt | 61   |
+-----+-----+-----+-----+------+

*specific options*

+---------------+----------------------------------------------------------+
| ``------x--`` | Mask scheme version                                      |
|               |                                                          |
| ``------1--`` | unencrypted |xin|                                        |
|               |                                                          |
| ``------0--`` | encryted |exin|                                          |
+---------------+----------------------------------------------------------+


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
| 20     | ephemeral hmac                                                  |
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
| 20     | encrypted |ai| : |eai|                                          |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+
| 20     | |aGi|                                                           |
+--------+-----------------------------------------------------------------+
| 20     | |IIi|                                                           |
+--------+-----------------------------------------------------------------+
| 20     | |aHi|                                                           |
+--------+-----------------------------------------------------------------+

for random ring key

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | encrypted |ai| : |eai|                                          |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+
| 20     | |aGi|                                                           |
+--------+-----------------------------------------------------------------+


MLSAG hash
^^^^^^^^^^^

**Description**

Compute the last matrix ring parameter:

   | if cnt == 1:
   |    replace the inputs by the previously computed MLSAG-prehash
   |    initialize |mlsagH|
   |
   | update |mlsagH|: |Hs|(inputs)
   |
   | if last command:
   |  c = finalize |mlsagH| % order

**Command**

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 84  | 02  | cnt | 21   |
+-----+-----+-----+-----+------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 20     | inputs                                                          |
+--------+-----------------------------------------------------------------+

**Response data**

if last command

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | c                                                               |
+--------+-----------------------------------------------------------------+

else

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

+-----+-----+-----+-----+------+
| CLA | INS | P1  | P2  | LC   |
+=====+=====+=====+=====+======+
| 02  | 84  | 03  | cnt | 81   |
+-----+-----+-----+-----+------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 20     | |exin|                                                          |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+
| 20     | |eai|                                                           |
+--------+-----------------------------------------------------------------+
| 20     | ephemeral hmac                                                  |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | signature |ss|                                                  |
+--------+-----------------------------------------------------------------+



Conclusion
==========

Let's Go

Annexes
=======

References
----------

   | [1] `<https://github.com/monero-project/monero/tree/v0.10.3.1>`_
   | [2] `<https://github.com/monero-project/monero/pull/2056>`_
   | [3] `<https://github.com/kenshi84/monero/tree/subaddress-v2>`_
   | [4] `<https://www.reddit.com/r/Monero/comments/6invis/ledger_hardware_wallet_monero_integration>`_
   | [5] `<https://github.com/moneroexamples>`_



Helper functions
----------------

**|keyDrv|**

   | *input* : :math:`r , P`
   | *output*:  :math:`\mathfrak{D}`
   | *Monero*: generate_key_derivation
   |
   |      :math:`\mathfrak{D} = r.P`
   |      :math:`\mathfrak{D} = 8.\mathfrak{D}`
   |


**|Hs|**

   | *input*: :math:`raw`
   | *output*: :math:`s`
   |
   |
   |      |s| = |H|(:math:`raw`)
   |

**|Hps|**

   | *input*: :math:`D, idx`
   | *output*: :math:`s`
   |
   |      :math:`data` = :math:`point2bytes(D) | varint(idx)` 
   |      |s| = |H|(:math:`data`) % order
   |


**|Hp|**

   | *input*: :math:`P`
   | *output*: :math:`Q`
   |
   |      :math:`data` = :math:`point2bytes(P)`
   |      |s| = |H|(:math:`data`) % order
   |      :math:`Q` = :math:`ge\_from\_fe(s)`


**DeriveAES**

   | *input*: :math:`R,a,b`
   | *output*: :math:`spk`
   |
   | :math:`seed` = :math:`sha256(R|a|b|R)`
   | :math:`data` = :math:`sha256(seed)`
   | :math:`spk`  = :math:`lower16(data)`
