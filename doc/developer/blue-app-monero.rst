
..
   Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
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


.. |A|      replace:: :math:`\mathit{A}`
.. |aa|     replace:: :math:`\mathit{a}`
.. |a.A|    replace:: :math:`(\mathit{a, A})`
.. |B|      replace:: :math:`\mathit{B}`
.. |bb|     replace:: :math:`\mathit{b}`
.. |b.B|    replace:: :math:`(\mathit{b, B})`
.. |c|      replace:: :math:`\mathit{c}`
.. |c.C|    replace:: :math:`(\mathit{c, C})`
.. |d|      replace:: :math:`\mathit{d}`
.. |d.D|    replace:: :math:`(\mathit{d, D})`
.. |ed|     replace:: :math:`\widetilde{\mathit{d}}`
.. |Aout|   replace:: :math:`\mathit{A_{out}}`
.. |Bout|   replace:: :math:`\mathit{B_{out}}`
.. |Dout|   replace:: :math:`\mathit{D_{out}}`
.. |Cout|   replace:: :math:`\mathit{C_{out}}`

.. |Tin|    replace:: :math:`\mathit{T_{in}}`
.. |Tout|   replace:: :math:`\mathit{T_{out}}`
.. |idx|    replace:: :math:`\mathit{idx}`
.. |x|      replace:: :math:`\mathit{x}`
.. |ex|     replace:: :math:`\widetilde{\mathit{x}}`
.. |P|      replace:: :math:`\mathit{P}`
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


.. |Rin|    replace:: :math:`\mathit{R_{in}}`
.. |R|      replace:: :math:`\mathit{R}`
.. |rr|     replace:: :math:`\mathit{r}`
.. |r.R|    replace:: :math:`(\mathit{r, R})`
.. |er|     replace:: :math:`\widetilde{\mathit{r}}`
.. |s|      replace:: :math:`\mathit{s}`

.. |spk|     replace:: :math:`\mathit{spk}`
.. |espk|    replace:: :math:`\widetilde{\mathit{spk}}`



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
.. |AKout|   replace::  :math:`\mathcal{AK}_\mathrm{amount}`
.. |eAKout|  replace:: :math:`\widetilde{\mathcal{AK}_\mathrm{amount}}`

.. |PayID|  replace:: :math:`\mathit{PayID}`
.. |ePayID| replace:: :math:`\widetilde{\mathit{PayID}}`

.. |Ct|     replace:: :math:`\mathit{C_v}`
.. |Ctf|    replace:: :math:`\mathit{C_v = k.G + v.H}`
.. |H|      replace:: :math:`\mathit{H}`
.. |h|      replace:: :math:`\mathit{h}`
.. |Hf|     replace:: :math:`\mathit{H = h.G}`

.. |G|      replace:: :math:`\mathit{G}`
.. |l|      replace:: :math:`\mathit{l}`
.. |v|      replace:: :math:`\mathit{v}`
.. |k|      replace:: :math:`\mathit{k}`
.. |ev|     replace:: :math:`\widetilde{\mathit{v}}`
.. |ek|     replace:: :math:`\widetilde{\mathit{k}}`

.. |Hs|     replace:: :math:`\mathtt{H_s}`
.. |Hp|     replace:: :math:`\mathtt{H_p}`
.. |Hps|    replace:: :math:`\mathtt{H_{p\to{s}}}`
.. |drvDH|  replace:: :math:`\mathtt{DeriveDH}`
.. |drvPu|  replace:: :math:`\mathtt{DerivePub}`
.. |drvPv|  replace:: :math:`\mathtt{DerivePriv}`
.. |drvIm|  replace:: :math:`\mathtt{DeriveImg}`
.. |enc|    replace:: :math:`\mathtt{AES}`
.. |dec|    replace:: :math:`\mathtt{AES^{-1}}`
.. |P2B|    replace:: :math:`\mathtt{PointToBYtes}`

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

   - |Hp| :              point to point hash function

   - |Hs| :              scalar to scalar hash function

   - |Hps| :             point to scalar hash function

   - |enc| :             [k](m) AES encryption of *m* with key *k*

   - |dec| :             [k](c) AES decryption of *c* with key *k*

Others:

   - |PayID| :           Stealth payment ID

   - |EPIT| :            0x82

Some helper functions:

   - |drvDH| :           Derivation function: scalar,point :math:`\to` point

   - |drvPu| :           Derivation function: scalar,point :math:`\to` point

   - |drvPv| :           Derivation function: point, scalar :math:`\to` scalar




|_pb|

State Machine
=============


**TBD**


|_pb|

Provisioning
============

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


Put keys
--------

Description
~~~~~~~~~~~

Put sender key pairs.

The application shall:

   | check  |A| ==  |aa|.|G|
   | check  |B| ==  |bb|.|G|
   | store |aa|, |A|, |bb|, |B|


Commands
~~~~~~~~

Get Public Key
^^^^^^^^^^^^^^
.. _GPK:

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
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 5f     | Base58 encoded public key                                       |
+--------+-----------------------------------------------------------------+

Get Secret Keys
^^^^^^^^^^^^^^^
.. _GSK:

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
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | Encrypted view key                                              |
+--------+-----------------------------------------------------------------+
| 20     | Encrypted send key                                              |
+--------+-----------------------------------------------------------------+


Put keys
--------

Description
~~~~~~~~~~~

Put sender key pairs.

The application shall:

   | check  |A| ==  |aa|.|G|
   | check  |B| ==  |bb|.|G|
   | store |aa|, |A|, |bb|, |B|


Commands
~~~~~~~~

Put Keys
^^^^^^^^
.. _PSK:

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


|_pb|

Integration
===========


Hereafter are the code integration and application specification. Each step is
detailed with client code references and matching device commands.

Note that in this process, the device will first see all input keys, then all
output keys, and will have to sign some data related to those seen keys. In
order to enforce that signed data is really bound to the input and out keys
processed during the first steps, an hash - named |lH| -  is computed during
the key processing then verified during the sign process. If the hash does not
match, the device will refuse to sign the transaction.

In the same way, we create an hash over commitment - named |ctH| - to ensure
that values between commitment validation and signing are the same.

Note that |lH| is required because the mlsag-prehash does not cover the
ephemeral destination key.


Common commands format
----------------------

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


Start transaction
-----------------


Code Reference
~~~~~~~~~~~~~~

.. _`cryptonote_tx_utils.cpp line 169`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L169

The transaction key is generated in  `cryptonote_tx_utils.cpp line 169`_.

This generation is simply delegated to NanoS which keeps the secret key.
During this step, the NanoS also computes a secret key SPK (Secret Protection
Key) to encrypt some confidential data for which the storage is delegated
to the Host.
Optionally the secret transaction key may be returned encrypted by SPK to be
used later. Moreover, the secret transaction key is discarded by the token at
the end of the transaction and can not be retrieved if not saved by host. If
the secret transaction key needs to be saved, the SPK is generated in a
deterministic way.

Finally, an optional exchange is done to override the TX public key in case
a Sub-Address is used.


Description
~~~~~~~~~~~

This is the very first APDU initiating a transaction signature. When receiving
this command, the application resets its internal state and aborts any
unfinished previous transaction. After resetting, the application generates a
new Ed25519 Transaction Key pair (r,R).

If the account parameter is different from zero, it specifies the BIP44 *account*
path:

 ``/0x8000002C/0x80000080/0x8......./0x00000000/0x00000000``

The account value shall be greater than *0x80000000*.

If the account parameter is equal to *zero*, and if external keys have been set with
the optional *Put Key* command, this keys are used.


If ``Keep r`` indicator is set, the application derives the protection key
|spk| with:

   | |spk| = DeriveAES(|R|,|aa|,|bb|)
   | |er| = AES[|spk|](|rr|)

If  ``Keep r`` indicator is not set, the application derives a random
protection key |spk|.

Finally the application returns |R| and optionally |eR|


A second command can be sent just after to switch to a destination sub-address.
When receiving this command, the application must compute the new transaction
public key according to the provided |Dout| sub-address.

   | |R| =  |rr|.|Dout|

The application returns the the new |R|.


Commands
~~~~~~~~

Open Transaction
^^^^^^^^^^^^^^^^
.. _OTX:

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  |  LC  | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 50  | 01  | 00  | 05   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 04     | account                                                         |
+--------+-----------------------------------------------------------------+

*option encoding*

+---------------+----------------------------------------------------------+
| ``-------x`` | ``Keep r``  indicator                                    |
|               |                                                          |
| ``-------1`` | Private TX key must be returned encrypted                |
|               |                                                          |
| ``-------0`` | Private TX key must not be returned                      |
+---------------+----------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | |R| key                                                         |
+--------+-----------------------------------------------------------------+
| 20     | |er|  if *Keep r* indicator is set                              |
+--------+-----------------------------------------------------------------+


Sub Transaction
^^^^^^^^^^^^^^^
.. _STX:

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 50  | 02  | 00  | 00   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+

**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | Sub address |Dout|                                              |
+--------+-----------------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | |R| key                                                         |
+--------+-----------------------------------------------------------------+


Process Stealth Payment
-----------------------

Code Reference
~~~~~~~~~~~~~~



Description
~~~~~~~~~~~

This command handles the Stealth Payment Encryption.

The application encrypts the paymentID with the following steps:

   | compute |DRVout| =  |drvDH|(|rr|,|Aout|)
   | compute |s| = |Hs|(|P2B|(|DRVout|) \| |EPIT| )
   | compute |epayID| = |payID| :math:`\oplus` |s|``[0:8]``



Commands
~~~~~~~~

Stealth
^^^^^^^
.. _SPI:

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 52  | 01  | 00  | 41   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | option                                                          |
+--------+-----------------------------------------------------------------+
| 20     | View destination address  |Aout|                                |
+--------+-----------------------------------------------------------------+
| 08     | clear payment ID |PayID|                                        |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 08     | encrypted payment ID  |ePayID|                                  |
+--------+-----------------------------------------------------------------+


Process Input Transaction Keys
------------------------------


Code Reference
~~~~~~~~~~~~~~

.. _`cryptonote_tx_utils.cpp line 225`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L225
.. _`cryptonote_tx_utils.cpp line 239`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L239
.. _`generate_key_image_helper`:       https://github.com/monero-project/monero/blob/v0.10.3.1/src/cryptonote_basic/cryptonote_format_utils.cpp#L132

For each |Tin|, The private spend key is retrieved in the loop `cryptonote_tx_utils.cpp line 225`_
by calling `generate_key_image_helper` (`cryptonote_tx_utils.cpp line 239`_).
The following commands allow to implement `generate_key_image_helper`_ in a secure way.

In order not to publish the |Tin| secret spend key |xin| to the host, the key is
returned encrypted by |spk|.

The commands take into account sub-address-v2 by first retrieving the public
derivation data, checking if it belongs or not to a sub-address then retrieving
the secret key and key image according to that.


Description
~~~~~~~~~~~

For each input |Tin|, the application receives the |Rin| transaction public key.

Once received the application SHALL verify that the public key is valid, i.e the
Point is on curve and its order is correct.

After checking the input transaction public key, the application computes the
public derivation data |DRVin| and returns it.

   | |DRVin| = |drvDH|(|aa|,|Rin|)


Just after this command, the application shall receive the request to compute
the signature key. In other word retrieve for the input transaction the triplet
|xin|, |Pin|, |Iin|. This command takes one argument: the sub-key index. Zero means
main spend key, non zero value means sub_key. Thus, the application processes the
command this way:

   | compute |xin| = |drvPv|(|DRVin|,|bb|)
   | if *idx != 0* :
   |    |xin| = |xin| + |Hs|(“subAddr” \| |aa| \| |idx|)
   | compute |Pin| = |xin|.|G|
   | compute |Iin| = |drvIm|(|xin|,|Pin|)
   | compute |exin| = |enc|[|spk|](|xin|)

Note that the application returns |exin|, i.e. |xin| protected by |spk|.

Commands
~~~~~~~~

Get key Derivation
^^^^^^^^^^^^^^^^^^
.. _GKD:


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 54  | 01  | cnt | 21   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | option                                                          |
+--------+-----------------------------------------------------------------+
| 20     | Public input transaction key |Rin|                              |
+--------+-----------------------------------------------------------------+

*option encoding*

+---------------+----------------------------------------------------------+
| ``-------xx`` | key to derive                                            |
|               |                                                          |
| ``-------01-``|  - secret view key                                       |
| ``-------10-``|  - secret view key                                       |
| ``-------11-``|  - given encrypted secret key                            |
|               |                                                          |
+---------------+----------------------------------------------------------+

**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | public input derivation data |DRVin|                            |
+--------+-----------------------------------------------------------------+

Get Input Keys
^^^^^^^^^^^^^^^
.. _GIK:


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 54  | 02  | cnt | 05   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | option                                                          |
+--------+-----------------------------------------------------------------+
| 08     | Sub-key Major.minor index, 0 means main key                     |
+--------+-----------------------------------------------------------------+
| 04     | real output index                                               |
+--------+-----------------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 20     | encrypted private input spend key |exin|                        |
+--------+-----------------------------------------------------------------+
| 20     | public input spend key |Pin|                                    |
+--------+-----------------------------------------------------------------+
| 20     | |Pin| key image |Iin|                                           |
+--------+-----------------------------------------------------------------+


Process Output Transaction Keys
-------------------------------


Code Reference
~~~~~~~~~~~~~~

.. _`cryptonote_tx_utils.cpp line 278`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L278
.. _`cryptonote_tx_utils.cpp line 287`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L287
.. _`generate_key_derivation`:
.. _`derive_public_key`:


For each output transaction, the destination key is computed by calling
generate_key_derivation in `cryptonote_tx_utils.cpp line 287`_ and and derive_public_key in `cryptonote_tx_utils.cpp line 287`_

In case of sub-address-v2 a dedicated interaction is done to retrieve the change address.
Note here, the derivation data must be kept secret as it is used to blind the amount.
The data is returned encrypted to the Host and must be stored in the tx as temporary
data (associated to the destination key) for the subsequent steps.


Description
~~~~~~~~~~~

Compute either the destination key or the change key.


If destination key is requested, perform the following:

   | compute |DRVout|    = |drvDH|(|rr|,|Aout|)


Else if change key is requested, perform the following:

   | compute |DRVout| = |drvDH|(|aa|,|R|)

Then

   | compute |AKout| = |Hps|(|DRVout|,|idx|)
   | compute |Pout|      = |drvPu|(|DRVout|,|Bout|)

Finally:

   | compute |eAKout| = |enc|[|spk|](|AKout|)
   | update  |lH| : |Hupd|(|Aout| \| |Bout|  \| |AKout| \| |Pout|)

In both cases, return |Pout| and |AKout|.




Get Output Keys
^^^^^^^^^^^^^^^
.. _GOK:


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 56  | 01  | cnt | 45   |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
+--------+-----------------------------------------------------------------+
| 20     | Destination view Key |Aout|                                     |
+--------+-----------------------------------------------------------------+
| 20     | Destination spend Key |Bout|                                    |
+--------+-----------------------------------------------------------------+
| 4      | output index                                                    |
+--------+-----------------------------------------------------------------+

*option encoding*

+---------------+----------------------------------------------------------+
| ``-------x-`` | Change key request                                       |
|               |                                                          |
| ``-------0-`` | Generate destination key                                 |
|               |                                                          |
| ``-------1-`` | Generate change key                                      |
+---------------+----------------------------------------------------------+


**Response data**

+--------+-----------------------------------------------------------------+
| Length |    Value                                                        |
+========+=================================================================+
| 20     | encrypted private amount key |eAKout|                           |
+--------+-----------------------------------------------------------------+
| 20     | public destination key |Pout|                                   |
+--------+-----------------------------------------------------------------+


Perform range proof and blinding
----------------------------------


Code Reference
~~~~~~~~~~~~~~

.. _`cryptonote_tx_utils.cpp line 450`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L450
.. _`rctSigs.cpp line L589`:             https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L589
.. _`rctSigs.cpp line L597`:             https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L597


Once |Tin| and |Tout| keys are set up, the genRCT function is called (`cryptonote_tx_utils.cpp line 450`_).

First a commitment |Ct| to each |v| amount, and associated range proof are computed
to ensure the |v| amount confidentiality. The commitment and its range proof do not
imply any secret and generate |Ct|, |k| such |Ctf| (`rctSigs.cpp line L589`_).

Then |k| and |v| are blinded by using the |AKout| which is only known in an encrypted
form by the host (`rctSigs.cpp L597`_).


Description
~~~~~~~~~~~

This command receives both the mask value and the amount to
blind, plus the encrypted private derivation data computed during the
processing of output transaction keys (GOK_).

The application performs the following steps:

   | compute |AKout| = |dec|[|spk|](|eAKout|)
   | compute |ek| = |k| + |Hs|(|AKout|)
   | compute |ev| = |k| + |Hs|(|Hs|(|AKout|))
   | update |lH| : |Hupd|(|v| \| |k| \| |AKout|)


The application returns |ev|, |ek|


Commands
~~~~~~~~

Blind Amount and Mask
^^^^^^^^^^^^^^^^^^^^^
.. _BAM:


**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 58  | 01  | cnt | var  |                                           |
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


MLSAG
-----

Code Reference
~~~~~~~~~~~~~~

.. _`rctSigs.cpp line 361`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L361
.. _`rctSigs.cpp line 362`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L362
.. _`rctSigs.cpp line 116`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L116
.. _`rctSigs.cpp line 191`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L191
.. _`rctSigs.cpp line 613`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L613

**Interaction overview**

After all commitments have been setup, the confidential ring signature happens.
This signature is performed by calling proveRctMG which calls
MLSAG_Gen

   | ProveRctMG : `rctSigs.cpp line 361`_
   | Call to MLSAG_Gen : `rctSigs.cpp line 362`_
   | MLSAG_Gen : `rctSigs.cpp line 116`_

At this point the amounts and destination keys must be validated on the NanoS. This
information is embedded in the message to sign by calling get_pre_mlsag_hash
at `rctSigs.cpp line 613`_, prior to calling ProveRctMG. So the get_pre_mlsag_hash
function will have to be modified to serialize the rv transaction to NanoS which
will validate the tuple <amount,dest> and compute the prehash.
The prehash will be kept inside NanoS to ensure its integrity.
Any further access to the prehash will be delegated.

Once the prehash is computed, the proveRctMG is called. This function only builds
some matrix and vectors to prepare the signature which is performed by the final
call MLSAG_Gen.

During this last step some ephemeral key pairs are generated : |ai|, |aGi|.
All |ai| must be kept secret to protect the x in keys.
Moreover we must avoid signing arbitrary values during the final loop
`rctSigs.cpp line 191`_

**Amount and destination validation**

In order to achieve this validation, we need to approve the original destination
address |Aout|, which is not recoverable from P out . Here the only solution is
to pass the original destination with the |k|, |v|. (Note this implies to add all
|Aout| in the rv structure).
So with |Aout|, we are able to recompute associated |Dout| (see step 3),
unblind |k| and |v| and then verify the commitment |Ctf|.
If |Ct| is verified and user validate |Aout| and |v|, |lH| is updated and we process
the next output.

**NanoS interaction**

.. _`rctSigs.cpp line 139`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L139
.. _`rctSigs.cpp line 158`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L158
.. _`rctSigs.cpp line 182`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L182
.. _`rctSigs.cpp line 142`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L142
.. _`rctSigs.cpp line 153`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L153
.. _`rctSigs.cpp line 148`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L148
.. _`rctSigs.cpp line 144`: https://github.com/monero-project/monero/blob/v0.10.3.1/src/ringct/rctSigs.cpp#L144


NanoS operates when manipulating the encrypted input secret key |xin|, the prehash, the |ai|
secret key and the final |mlsagH|. So the last function to modify is the MLSAG_Gen.
The message (prehash |mlsagH|) is held by the NanoS. So the vector initialization must be skipped
and the two calls to hash_to_scalar(toHash) must be modified

   - init: `rctSigs.cpp line 139`_
   - call 1: `rctSigs.cpp line 158`_
   - call 2: `rctSigs.cpp line 182`_

The |ai| , |aGi| generation is delegated to NanoS:

   - call 1: `rctSigs.cpp line 142`_
   - call 2: `rctSigs.cpp line 153`_

As consequence point computation line 144 (`rctSigs.cpp line 144`) is also delegated.
Finally the key Image computation must be delegated to the NanoS: `rctSigs.cpp line 148`


Description
~~~~~~~~~~~

**Part 1: prehash**

Validate the destinations and amounts and compute the MLSAG prehash value.

This final part is divided in three steps.

During the first step, the application updates the |mlsagH|  with the transaction
header (`SBE`_):

   | finalize |lH| : |Hfin|()
   | update |mlsagH| : |Hupd|(:math:`header`)

On the second step (`SAP`_) the application receives amount and destination and check
values. It also re-compute the |lH| value to ensure consistency with steps 3 and 4.
So for each command received, do:

   | compute |DRVout| =  |drvDH|(|rr|,|Aout|)`
   | compute |k| = |ek| - |Hps|(|DRVout|)
   | compute |v| = |ek| - |Hs|(|Hps|(|DRVout|))
   | check |Ctf|

   | ask user validation of |Aout|, |Bout|
   | ask user validation of |v|

   | update |ctH| : |Hupd|(|Ct|)
   | update |lH| : |Hupd|(|Aout| \| |Bout| \| |DRVout| \| |v| \| |k| \| |DRVout|)

   | update |mlsagH| : |Hupd|(:math:`ecdhInfo`)

Finally the application receives the last part of data (`SEN`_):

   | finalize |lH|' : |Hfin|()
   | check |lH| == |lH|'

   | finalize |ctH| : |Hfin|()
   | compute |ctH|' = |Hfin|(:math:`commitment_0.Ct  | commitment_1.Ct | .....`)                                                           |
   | check |ctH| == |ctH|'

   | finalize |mlsagH| : |Hfin|(:math:`commitments`)
   | compute |mlsagH| = |H|(:math:`message` \| |mlsagH| \| :math:`proof`)


Keep |mlsagH|

**Part 2: signature**

Step 1:

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

Step 2:

Compute the last matrix ring parameter:

   | replace the first 32 bytes of ``inputs`` by the previously computed MLSAG-prehash
   | compute c = |H|(``inputs``)



Step 3:

Finally compute all signatures:

    | compute |ai|  = |dec|[|spk|](|eai|)
    | compute |xin| = |dec|[|spk|](|exin|)
    | compute |ss|  = (|ai| - |c| * |xin| ) % |l|

return |ss|


Commands
~~~~~~~~

Initialize MLSAG-prehash
^^^^^^^^^^^^^^^^^^^^^^^^

.. _`SBE`:

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 5A  | 01  | cnt  | var  |                                           |
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

.. _`SAP`:

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 5A  | 02  | cnt | var  |                                           |
+-----+-----+-----+-----+------+-------------------------------------------+


**Command data**

+--------+-----------------------------------------------------------------+
| Length | Value                                                           |
+========+=================================================================+
| 01     | options                                                         |
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

.. _`SEN`:

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 5A  | 03  | 00  | var  |                                           |
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


MLSAG prepare
^^^^^^^^^^^^^^

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 5C  | 01  | cnt | var  |                                           |
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

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 5C  | 02  | 00  | var  |                                           |
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

**Command**

+-----+-----+-----+-----+------+-------------------------------------------+
| CLA | INS | P1  | P2  | LC   | data description                          |
+=====+=====+=====+=====+======+===========================================+
| 00  | 5C  | 03  | cnt | var  |                                           |
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

Annexes
=============

Helper functions
----------------

**DeriveDH**

   | *input* : :math:`r , P`
   | *output*:  :math:`\mathfrak{D}`
   | *Monero*: generate_key_derivation
   |
   |      :math:`\mathfrak{D} = r.P`
   |      :math:`\mathfrak{D} = 8.\mathfrak{D}`
   |

**DerivePub**

   | *input*: :math:`\mathfrak{D},B`
   | *output*: :math:`P`
   | *Monero*: derive_public_key
   |
   |      :math:`P` = |Hps|:math:`(\mathfrak{D}).G+B`
   |


**DerivePriv**

   | *input*: D,b
   | *output*: x
   | *Monero*: derive_private_key
   |
   |      :math:`x` = |Hps|:math:`(\mathfrak{D})+b`
   |

**DeriveImg**

   | *input*: :math:`x,P`
   | *output*: :math:`I`
   | *Monero*:
   |
   |      :math:`I` = |xin|.|Hp|(|Pin|)
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
   |      |s| = |H|(:math:`data`)
   |


**|Hp|**

   | *input*: :math:`P`
   | *output*: :math:`Q`
   |
   |      :math:`data` = :math:`KindOfMagic(P)`


**DeriveAES**

This is just a quick proposal. Any other KDF based on said standard may take place here.

   | *input*: :math:`R,a,b`
   | *output*: :math:`spk`
   |
   | :math:`seed` = :math:`sha256(R|a|b|R)`
   | :math:`data` = :math:`sha256(seed)`
   | :math:`spk`  = :math:`lower16(data)`

References
----------

   | [1] `<https://github.com/monero-project/monero/tree/v0.10.3.1>`_
   | [2] `<https://github.com/monero-project/monero/pull/2056>`_
   | [3] `<https://github.com/kenshi84/monero/tree/subaddress-v2>`_
   | [4] `<https://www.reddit.com/r/Monero/comments/6invis/ledger_hardware_wallet_monero_integration>`_
   | [5] `<https://github.com/moneroexamples>`_
