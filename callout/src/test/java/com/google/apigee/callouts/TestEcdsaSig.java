// TestEcdsaSig.java
//
// Test code for the ECDSA signing custom policy for Apigee. Uses TestNG.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2019-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.MessageContext;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TestEcdsaSig {

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  MessageContext msgCtxt;
  ExecutionContext exeCtxt;

  @BeforeMethod()
  public void testSetup1() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map<String, Object> variables;

          public void $init() {
            getVariables();
          }

          private Map<String, Object> getVariables() {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            return variables;
          }

          @Mock()
          public Object getVariable(final String name) {
            Object o = getVariables().get(name);
            System.out.printf(
                "getVariable(%s) => %s\n", name, (o == null) ? "-null-" : o.toString());
            return o;
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            System.out.printf(
                "setVariable(%s) <= %s\n", name, (value == null) ? "-null-" : value.toString());
            getVariables().put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (getVariables().containsKey(name)) {
              System.out.printf("removeVariable(%s)\n", name);
              variables.remove(name);
            }
            return true;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();
    System.out.printf("=============================================\n");
  }

  static class PairedKeys {
    public String privateKey;
    public String publicKey;

    public PairedKeys(String privateKey, String publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }
  }

  private static PairedKeys[] testkeys =
      new PairedKeys[] {
        new PairedKeys(
            "-----BEGIN PRIVATE KEY-----\n"
                + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLsZ/mjo3Skwk6C8N\n"
                + "hv6E0oJt1QpuT6yuUpEi27YqKcihRANCAARqx3u8pCQtmOAGJUiKGwrbaU+vAfnn\n"
                + "Top8ZN3Kt0pG/0qOHn0W2v/MUmb0rH+XzjJhWOJxkV7AyIddYpNieXxv\n"
                + "-----END PRIVATE KEY-----\n",
            "-----BEGIN PUBLIC KEY-----\n"
                + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEasd7vKQkLZjgBiVIihsK22lPrwH5\n"
                + "506KfGTdyrdKRv9Kjh59Ftr/zFJm9Kx/l84yYVjicZFewMiHXWKTYnl8bw==\n"
                + "-----END PUBLIC KEY-----\n"),
        new PairedKeys(
            "-----BEGIN PRIVATE KEY-----\n"
                + "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAVhWPkn/MUR8sgRsN\n"
                + "G7DTXkGAHbKDCK6GEzXVCLqfiMDgddAGYopX16qMB/AO2VAwHigz0UI4lnIEkW4t\n"
                + "Q4JeT/ahgYkDgYYABAGfiOKvHqR5WEOBTmLfEOdkZpMb+TXfepb7IFu/gOESQoBT\n"
                + "oYtbcVQCkew/emFOv2FIIDG57E2Q0P1lJk5NFjo0wACrAQLbQv65FjIRegjLnq/P\n"
                + "u4sv1BpsAv3BKE2Ivcy5OQGcuho5Ef+5hNHF59MnpyuE0YuLsZwe17uncv+H6Ukb\n"
                + "MA==\n"
                + "-----END PRIVATE KEY-----\n",
            "-----BEGIN PUBLIC KEY-----\n"
                + "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBn4jirx6keVhDgU5i3xDnZGaTG/k1\n"
                + "33qW+yBbv4DhEkKAU6GLW3FUApHsP3phTr9hSCAxuexNkND9ZSZOTRY6NMAAqwEC\n"
                + "20L+uRYyEXoIy56vz7uLL9QabAL9wShNiL3MuTkBnLoaORH/uYTRxefTJ6crhNGL\n"
                + "i7GcHte7p3L/h+lJGzA=\n"
                + "-----END PUBLIC KEY-----\n"),
        new PairedKeys(
            "",
            "      -----BEGIN PUBLIC KEY-----\n"
                + "      MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBHPYWDznBjvs9Wl7Nw51DI90D7G+7JQCIssdj5nkt\n"
                + "      Q+KgBZsQ28eWkJyEBz0oSquTa876XXA9C8N3F0CQs6UgrrQAMfuuFS6b/XJH3RolJVZNdN7xmZxG\n"
                + "      hbP+sz75nIB1NVym5y7nRgzyUxX2FPo7PoRAlWZQM2V6CDt6NdUFLHHM19U=\n"
                + "      -----END PUBLIC KEY-----\n")
      };

  private void reportThings(Map<String, String> props) {
    String test = props.get("testname");
    System.out.println("test  : " + test);
    String action = msgCtxt.getVariable("ecdsa_action");
    System.out.println("action: " + action);
  }

  @Test()
  public void sign_SourceVarNotDefined() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_SourceVarNotDefined");
    properties.put("action", "sign");
    // properties.put("debug", "false");
    properties.put("generate-keypair", "true");
    properties.put("encode-result", "base16");
    properties.put("source", "unset_variable");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "source 'unset_variable' resolves to null");
  }

  @Test()
  public void sign_GenerateKeypair_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_GenerateKeypair_Base16");
    properties.put("action", "sign");
    properties.put("debug", "true");
    properties.put("generate-keypair", "true");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);

    String encodedPublicKey = msgCtxt.getVariable("ecdsa_output_publickey");
    Assert.assertNotNull(encodedPublicKey);
    String encodedPrivateKey = msgCtxt.getVariable("ecdsa_output_privatekey");
    Assert.assertNotNull(encodedPrivateKey);
  }

  @Test()
  public void sign_GenerateKeypair_secp521r1_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_GenerateKeypair_secp521r1_Base16");
    properties.put("action", "sign");
    properties.put("debug", "true");
    properties.put("generate-keypair", "true");
    properties.put("curve", "secp521r1");
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);
    String computedSig = msgCtxt.getVariable("ecdsa_signature");
    Assert.assertNotNull(computedSig);

    String encodedPublicKey = msgCtxt.getVariable("ecdsa_output_publickey");
    Assert.assertNotNull(encodedPublicKey);
    String encodedPrivateKey = msgCtxt.getVariable("ecdsa_output_privatekey");
    Assert.assertNotNull(encodedPrivateKey);
  }

  @Test()
  public void sign_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_Base16");
    properties.put("action", "sign");
    properties.put("debug", "true");
    properties.put("generate-keypair", "false");
    properties.put("private-key", testkeys[0].privateKey);
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);
    String computedSig = msgCtxt.getVariable("ecdsa_signature");
    Assert.assertNotNull(computedSig);

    String encodedKey = msgCtxt.getVariable("ecdsa_output_privatekey");
    Assert.assertNull(encodedKey);
  }

  @Test()
  public void verify_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_Base16");
    properties.put("action", "verify");
    properties.put("debug", "true");
    properties.put("source", "message.content");
    properties.put("signature", "{signature_value}");
    properties.put("decode-signature", "base16");
    properties.put("public-key", testkeys[0].publicKey);

    msgCtxt.setVariable(
        "signature_value",
        "304502210082b5f9a51c0f8494f23faea1b7efed20e18292d2d2b79e680c764b68bab437d002205030659eff9cc0a6404a64809b021827c3d3e8b92220a6b5e3d98b4cd7d8e97b");
    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);
    String verified = msgCtxt.getVariable("ecdsa_verified");
    Assert.assertNotNull(verified);
    Assert.assertEquals(verified.toUpperCase(), "TRUE");
  }

  @Test()
  public void sign_secp521r1_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "sign_secp521r1_Base16");
    properties.put("action", "sign");
    properties.put("debug", "true");
    properties.put("generate-keypair", "false");
    properties.put("curve", "secp521r1");
    properties.put("private-key", testkeys[1].privateKey);
    properties.put("encode-result", "base16");

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);

    String encodedKey = msgCtxt.getVariable("ecdsa_output_privatekey");
    Assert.assertNull(encodedKey);
  }

  @Test()
  public void verify_secp521r1_Base16() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_secp521r1_Base16");
    properties.put("action", "verify");
    properties.put("debug", "true");
    properties.put("signature", "{signature_value}");
    properties.put("decode-signature", "base16");
    properties.put("public-key", testkeys[1].publicKey);

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog.");
    msgCtxt.setVariable(
        "signature_value",
        "3081870242012173639d92d6fd7e077e82f6cc74cbf994b27e5d6074b9798f4a6ee3bacc4210d97a3a045e902fba4f2e8ccc4e2be98816d6b4dcc10e93c4a7abb43adacf57af6302417fe40bb5b64d0edc1f7716bd3d625e9cf66d887cfeef9d7bfde39487a9b93ee3e194e8702a04e66e957c9cc057d3de9cf3650a8037b3e6ad14b75f0aa7938ce2d7");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);

    String verified = msgCtxt.getVariable("ecdsa_verified");
    Assert.assertNotNull(verified);
    Assert.assertEquals(verified.toUpperCase(), "TRUE");
  }

  @Test()
  public void verify_secp521r1_Base16_fail() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_secp521r1_Base16_fail");
    properties.put("action", "verify");
    properties.put("debug", "true");
    properties.put("signature", "{signature_value}");
    properties.put("decode-signature", "base16");
    properties.put("public-key", testkeys[1].publicKey);

    msgCtxt.setVariable("message.content", "The quick brown fox jumped over the lazy dog...");
    msgCtxt.setVariable(
        "signature_value",
        "3081870242012173639d92d6fd7e077e82f6cc74cbf994b27e5d6074b9798f4a6ee3bacc4210d97a3a045e902fba4f2e8ccc4e2be98816d6b4dcc10e93c4a7abb43adacf57af6302417fe40bb5b64d0edc1f7716bd3d625e9cf66d887cfeef9d7bfde39487a9b93ee3e194e8702a04e66e957c9cc057d3de9cf3650a8037b3e6ad14b75f0aa7938ce2d7");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "verification of the signature failed.");

    String verified = msgCtxt.getVariable("ecdsa_verified");
    Assert.assertNotNull(verified);
    Assert.assertEquals(verified.toUpperCase(), "FALSE");
  }

  @Test()
  public void verify_secp521r1_P1363_Base64() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_secp521r1_P1363_Base64");
    properties.put("action", "verify");
    properties.put("format", "P1363");
    properties.put("debug", "true");
    properties.put("signature", "{signature_value}");
    properties.put("decode-signature", "base64");
    properties.put("public-key", testkeys[2].publicKey);

    msgCtxt.setVariable("message.content", "Live long and prosper");
    msgCtxt.setVariable(
        "signature_value",
        "AEYo2JeQXtEG3sMf5uISVd+Iri2Sq6h9lmibWAtpGkNwI6gtqnASMaGPnE6fdvPM9tqzWzPeMCONASz+Zr1pUATiAGKLUPBb25XLVBXDBeCbRk94gvkZ2pZWbtvCWNuaWl3MfBglySTj0bTy43IqB0Q5J2dS+RuVFmGEZOq84o5uy5py");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);

    String verified = msgCtxt.getVariable("ecdsa_verified");
    Assert.assertNotNull(verified);
    Assert.assertEquals(verified.toUpperCase(), "TRUE");
  }

  public void verify_secp521r1_ASN1_Base64() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "verify_secp521r1_ASN1_Base64");
    properties.put("action", "verify");
    properties.put("debug", "true");
    properties.put("signature", "{signature_value}");
    properties.put("decode-signature", "base64");
    properties.put("public-key", testkeys[2].publicKey);

    msgCtxt.setVariable("message.content", "Live long and prosper");
    msgCtxt.setVariable(
        "signature_value",
        "MIGGAkFGKNiXkF7RBt7DH+biElXfiK4tkquofZZom1gLaRpDcCOoLapwEjGhj5xOn3bzzPbas1sz3jAjjQEs/ma9aVAE4gJBYotQ8FvblctUFcMF4JtGT3iC+RnallZu28JY25paXcx8GCXJJOPRtPLjcioHRDknZ1L5G5UWYYRk6rzijm7LmnI=");

    EcdsaSigCallout callout = new EcdsaSigCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ecdsa_error");
    Assert.assertNull(error);

    String verified = msgCtxt.getVariable("ecdsa_verified");
    Assert.assertNotNull(verified);
    Assert.assertEquals(verified.toUpperCase(), "TRUE");
  }
}
