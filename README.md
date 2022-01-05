# ECDSA Signature callout

This directory contains the Java source code for a custom policy for Apigee that
performs ECDSA signature creation and verification of data or message payloads,
using `SHA256withECDSA`.  It can sign or verify with any EC curve supported by
the JDK.  This callout does not perform RSA signing, or ECDSA encryption.  It does not
sign with `SHA1withECDSA`.

An ECDSA signature is a [combination of two big
integers](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm),
known as `r` and `s`. There are multiple ways to format a signature. One common
way is to encode them via an ASN.1 DER sequence.  The other common way is to
simply concatenate the (r,s) integers.

This custom policy supports both for both input and output of signatures.  ASN.1
DER is the default format that this custom policy uses, for both input and
output.

## License

This code is Copyright (c) 2017-2021 Google LLC, and is released under the
Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using the Custom Policy

You do not need to build the Jar in order to use the custom policy.

When you use the policy to compute a signature using an ECDSA private key, the
resulting signature can be verified by other systems that have access to the
corresponding public key. Conversely, when you generate an ECDSA signature using
another system, this policy can verify the signature, if you configure it with
the corresponding public key.


## Policy Configuration

There are a variety of options, which you can select using Properties in the
configuration. Examples follow, but here's a quick summary:

- the policy uses as its source, the message.content. If you wish to sign
  something else, or verify the signature on something else, specify it with the
  source property.

- when using the policy for signing, you can specify the private key via a
  PEM-encoded string. When using the policy for verification, you can specify
  the public key via a PEM-encoded string. Examples:

  Private key:
  ```
  -----BEGIN PRIVATE KEY-----
  MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLsZ/mjo3Skwk6C8N
  hv6E0oJt1QpuT6yuUpEi27YqKcihRANCAARqx3u8pCQtmOAGJUiKGwrbaU+vAfnn
  Top8ZN3Kt0pG/0qOHn0W2v/MUmb0rH+XzjJhWOJxkV7AyIddYpNieXxv
  -----END PRIVATE KEY-----
  ```

  Public Key:
  ```
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEasd7vKQkLZjgBiVIihsK22lPrwH5
  506KfGTdyrdKRv9Kjh59Ftr/zFJm9Kx/l84yYVjicZFewMiHXWKTYnl8bw==
  -----END PUBLIC KEY-----
  ```

- you can also specify these PEM-encoded keys via variable references, using curly-braces.

- when using the policy for signing, you can specify the desired encoding
  (base64, base64url, base16) for the output signature. Similarly, when using
  the policy for verification, you can specify the way to decode the signature.


## Example: Verification of a Signature formatted in ASN.1

```xml
<JavaCallout name="Java-EcdsaVerify">
  <Properties>
    <Property name='action'>verify</Property>
    <Property name='source'>message.content</Property>
    <Property name='public-key'>
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEasd7vKQkLZjgBiVIihsK22lPrwH5
      506KfGTdyrdKRv9Kjh59Ftr/zFJm9Kx/l84yYVjicZFewMiHXWKTYnl8bw==
      -----END PUBLIC KEY-----
    </Property>
    <Property name='signature'>{signature_value}</Property>
    <Property name='decode-signature'>base16</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.EcdsaSigCallout</ClassName>
  <ResourceURL>java://apigee-callout-ecdsa-sig-20220104.jar</ResourceURL>
</JavaCallout>
```

Here's what will happen with this policy configuration:

* The `action` is `verify`, so the policy will verify a signature.

* The `source` property is specified as "message.content", therefore this policy
  will verify a signature over the message.content.

* The `signature` property specifies the signature to verify. It's a simple name
  specified in curly braces, referring to a context variable of that name.

* There is no `format` property, therefore the policy will decode the signature
  from ASN.1 DER format.

* The `decode-signature` value tells the policy to decode the signature value from
  a base16 string, resulting in a byte array. Your base16-encoded (aka hex-encoded) string
  can be uppercase or lowercase, and can include intervening dashes. These forms are all
  treated equivalently:
  * `30-45-02-21-00-82-b5-f9-a5-1c...`
  * `304502210082b5f9a51c...`
  * `304502210082B5F9A51C...`
  
  You cannot include arbitrary dashes in base64 or base64url-encoded strings.
  
* When verifying a signature, you must specify a public key. With the above
  configuration, the policy will deserialize the public key from the PEM string
  specified in the policy configuration.

If the signature verifies,  the policy will set the `ecdsa_verified` variable as "true".
If the signature does not verify,  the policy will set the `ecdsa_verified` variable to "false",
and will throw a fault.

## Example: Verification of a Signature formatted as P1363

If you want to verify a signature generated by [the .NET library](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa.signdata?view=net-5.0#System_Security_Cryptography_ECDsa_SignData_System_Byte___System_Int32_System_Int32_System_Security_Cryptography_HashAlgorithmName_System_Security_Cryptography_DSASignatureFormat_) which emits a
IEEE P1363-formatted signature (simply concatenating the (r,s) pair), you need to specify that in the policy configuration with the `format` property, as in the following example.

```xml
<JavaCallout name="Java-EcdsaVerify">
  <Properties>
    <Property name='action'>verify</Property>
    <Property name='source'>message.content</Property>
    <Property name='format'>P1363</Property>
    <Property name='public-key'>
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEasd7vKQkLZjgBiVIihsK22lPrwH5
      506KfGTdyrdKRv9Kjh59Ftr/zFJm9Kx/l84yYVjicZFewMiHXWKTYnl8bw==
      -----END PUBLIC KEY-----
    </Property>
    <Property name='signature'>{signature_value}</Property>
    <Property name='decode-signature'>base16</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.EcdsaSigCallout</ClassName>
  <ResourceURL>java://apigee-callout-ecdsa-sig-20220104.jar</ResourceURL>
</JavaCallout>
```

## Example: Signing, while generating an EC key

```xml
<JavaCallout name="Java-Ecdsa-Generate-Key-and-Sign">
  <Properties>
    <Property name='action'>sign</Property>
    <Property name='generate-keypair'>true</Property>
    <Property name='encode-result'>base64</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.EcdsaSigCallout</ClassName>
  <ResourceURL>java://apigee-callout-ecdsa-sig-20220104.jar</ResourceURL>
</JavaCallout>
```

Here's what will happen with this policy configuration:

* the `action` is sign, so the policy will sign.

* there is no `source` property, so the policy will use `message.content` as the payload to sign.

* there is no `curve` property, so the policy will use the EC curve `prime256v1` when generating the keypair.

* the `generate-keypair` property is true, so the policy will generate an ECDSA
  keypair, and use the generated private key to sign. It also emits this private
  key into a context variable, `ecdsa_output_privatekey`, and emits the public
  key into a context variable, `ecdsa_output_publickey`.

* the `encode-result` property is base64, so the policy will emit the signature
  as a base64-encoded string, into `ecdsa_signature`.

## Example: Signing, while generating an EC key with a specific curve

```xml
<JavaCallout name="Java-Ecdsa-Generate-Key-and-Sign">
  <Properties>
    <Property name='action'>sign</Property>
    <Property name='curve'>secp521r1</Property>
    <Property name='generate-keypair'>true</Property>
    <Property name='encode-result'>base64</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.EcdsaSigCallout</ClassName>
  <ResourceURL>java://apigee-callout-ecdsa-sig-20220104.jar</ResourceURL>
</JavaCallout>
```

This is as above, but the policy will generate a keypair for the EC curve named `secp521r1`.


### Full Properties List

These are the properties available on the policy:

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| action            | required. either "verify" or "sign".                                                                                                              |
| public-key        | required when action = "verify". a PEM string representing the ECDSA public key.                                                                  |
| private-key       | required when action = "sign". a PEM string representing the ECDSA private key.                                                                   |
| private-key-password | optional. a password to use with an encrypted private key.                                                                                     |
| source            | optional. name of the context variable containing the data to sign or verify. Do not surround in curly braces. Defaults to `message.content`.     |
| decode-source     | optional. if present, one of "base16", "base64", or "base64url", to decode from a string to an octet stream. Otherwise, decoded as UTF-8.         |
| generate-keypair  | optional. a boolean. Meaningful only when action = "sign". If true, the policy generates a random ECDSA key pair for you, and emits the encoded private and public key into context variables. |
| curve             | optional. When `generate-keypair` is true, this specifies the name of the EC curve to use.  Such as: `prime256v1`, `secp521r1`, and so on. Defaults to `prime256v1`.  Ignored when `generate-keypair` is false or not present.      |
| format            | optional. One of {P1363, ASN1}. The format for the signature, either for reading or writing.  ASN1 DER is the default.                            |
| encode-result     | optional. One of {base16, base64, base64url}. The default is to not encode the result.                                                            |
| debug             | optional. true or false. If true, the policy emits extra context variables.                                                                       |


## Detecting Success and Errors

When action = `sign`, if the policy succeeds, it sets a variable `ecdsa_signature`
with the computed signature, encoded according to your `encode-result` setting
(base16, base64, base64url). In this case, if you also have `generate-keypair`
as true, then the policy will also set `ecdsa_output_privatekey` and
`ecdsa_output_publickey` to contain the PEM-encoded keys.  If you don't set
`generate-keypair` or set it to false, then the policy does not set these output
variables.

The policy will return ABORT and set the context variable `ecdsa_error` if there
has been any error at runtime. Your proxy bundles can check this variable in
`FaultRules`.

Errors can result at runtime if:

* you do not specify an `action` property, or the `action` is neither `sign` nor `verify`
* you pass an invalid string for the public key or private key, or the key does not match the curbe.
* you specify `action` = verify, and don't supply a `public-key`
* you specify `action` = sign, and don't supply a `private-key`
* you use a `decode-*` parameter that is none of {base16, base64, base64url}
* some other configuration value is null or invalid

## Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use
[maven](https://maven.apache.org/download.cgi) to do so. The build requires
JDK8. Before you run the build the first time, you need to download the Apigee
dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy the jar file for the custom
policy (found in callout/target/apigee-callout-ecdsa-sig-20220104.jar) to your
apiproxy/resources/java directory.  If you don't edit proxy bundles offline,
upload that jar file into the API Proxy via the Apigee API Proxy Editor .


## Build Dependencies

* Apigee expressions v1.0
* Apigee message-flow v1.0
* Bouncy Castle 1.67

These jars are specified in the pom.xml file.

The BouncyCastle jar is available as part of the Apigee runtime, although it is
not a documented part of the Apigee platform and is therefore not guaranteed to
remain available. In the highly unlikely future scenario in which Apigee removes
the BC jar from the Apigee runtime, you could simply upload the BouncyCastle jar
as a resource, either with the apiproxy or with the organization or environment,
to resolve the dependency.


## Author

Dino Chiesa
godino@google.com


## Bugs & Limitations

* The tests are incomplete. They don't test keys using a wide variety of curves. They don't test
  a wide variety of failure scenarios.
