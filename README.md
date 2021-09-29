# ECDSA Signature callout

This directory contains the Java source code for a custom policy for Apigee
that performs ECDSA signature creation and verification of data or message payloads.
It can sign or verify with any EC curve supported by the JDK.
This callout does not perform RSA signing, or ECDSA encryption.

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

- you can also specify these pem-encoded keys via variable references, using curly-braces.

- when using the policy for signing, you can specify the desired encoding
  (base64, base64url, base16) for the output signature. Similarly, when using
  the policy for verification, you can specify the way to decode the signature.



## Example: Basic Verification of a Signature

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
  <ResourceURL>java://apigee-callout-ecdsa-sig-20210929.jar</ResourceURL>
</JavaCallout>
```

Here's what will happen with this policy configuration:

* the `action` is `verify`, so the policy will verify a signature.
* The `source` property is specified as "message.content", therefore this policy will verify a signature over the message.content.
* When verifying a signature, you must specify a public key. With the above configuration, the policy will deserialize the public key from the PEM string specified in the policy configuration.
* The signature value is a byte array.  The `decode-signature` value tells the policy to decode the signature as a base16 string.
* The curve property is not specified, so the policy defaults to using "prime256v1" as the EC curve.

If the signature verifies,  the policy will set the `ecdsa_verified` variable as "true".
If the signature does not verify,  the policy will set the `ecdsa_verified` variable to "false",
and will throw a fault.


## Example: Signing, while generating an EC key

```xml
<JavaCallout name="Java-Ecdsa-Generate-Key-and-Sign">
  <Properties>
    <Property name='action'>sign</Property>
    <Property name='generate-keypair'>true</Property>
    <Property name='encode-result'>base64</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.EcdsaSigCallout</ClassName>
  <ResourceURL>java://apigee-callout-ecdsa-sig-20210929.jar</ResourceURL>
</JavaCallout>
```

Here's what will happen with this policy configuration:

* the `action` is sign, so the policy will sign.

* there is no `source` property, so the policy will use `message.content` as the payload to sign.

* there is no `curve` property, so the policy will use the EC curve `prime256v1`.

* the `generate-keypair` property is true, so the policy will generate an ECDSA
  keypair, and use the generated private key to sign. It also emits this private
  key into a context variable, `ecdsa_output_key`.

* the `encode-result` property is base64, so the key and signature will both be emitted as
  base64-encoded strings, `ecdsa_output_key` and `ecdsa_signature`.


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
  <ResourceURL>java://apigee-callout-ecdsa-sig-20210929.jar</ResourceURL>
</JavaCallout>
```

This is as above, but the policy will use the EC curve named `secp521r1`.


### Full Properties List

These are the properties available on the policy:

| Property          | Description                                                                                                                                       |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| action            | required. either "verify" or "sign".                                                                                                              |
| public-key        | required when action = "verify". a PEM string representing the ECDSA public key.                                                                  |
| private-key       | required when action = "sign". a PEM string representing the ECDSA private key.                                                                   |
| private-key-password | optional. a password to use with an encrypted private key.                                                                                     |
| source            | optional. name of the context variable containing the data to sign or verify. Do not surround in curly braces. Defaults to `message.content`.     |
| curve             | optional. name of the EC curve.  Example: prime256v1, secp521r1, and so on.     |
| decode-source     | optional. if present, one of "base16", "base64", or "base64url", to decode from a string to an octet stream. Otherwise, decoded as UTF-8.         |
| generate-keypair  | optional. a boolean. Meaningful only when action = "sign". If true, the policy generates a random ECDSA key pair, and emits the encoded private key. |
| encode-result     | optional. One of {base16, base64, base64url}. The default is to not encode the result.                                                            |
| debug             | optional. true or false. If true, the policy emits extra context variables. Not for use in production.                                            |


## Detecting Success and Errors

The policy will return ABORT and set the context variable `ecdsa_error` if there has been any error at runtime. Your proxy bundles can check this variable in `FaultRules`.

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

If you do wish to build the jar, you can use [maven](https://maven.apache.org/download.cgi) to do so. The build requires JDK8. Before you run the build the first time, you need to download the Apigee dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy the jar file for the custom
policy (found in callout/target/apigee-callout-ecdsa-sig-20210929.jar) to your
apiproxy/resources/java directory.  If you don't edit proxy bundles offline,
upload that jar file into the API Proxy via the Apigee API Proxy Editor .


## Build Dependencies

* Apigee expressions v1.0
* Apigee message-flow v1.0
* Bouncy Castle 1.64

These jars are specified in the pom.xml file.

The first two JARs are builtin to Apigee. You will need to upload the
BouncyCastle jar as a resource to your Apigee instance, either
with the apiproxy or with the organization or environment.


## Author

Dino Chiesa
godino@google.com


## Bugs & Limitations

* The tests are incomplete. They don't test a wide variety of curves. They don't test
  a wide variety of failure scenarios.
