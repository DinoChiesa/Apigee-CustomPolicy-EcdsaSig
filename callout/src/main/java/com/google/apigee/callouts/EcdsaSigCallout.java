// EcdsaSigCallout.java
//
// This is the main callout class for the ECDSA signature custom policy for Apigee.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2019-2021 Google LLC.
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
// @author: Dino Chiesa
//

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.encoding.Base16;
import com.google.apigee.util.CalloutUtil;
import com.google.apigee.util.KeyUtil;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.openssl.PEMWriter;

@IOIntensive
public class EcdsaSigCallout implements Execution {
  private static final String varprefix = "ecdsa_";

  private static final Pattern variableReferencePattern =
      Pattern.compile("(.*?)\\{([^\\{\\} :][^\\{\\} ]*?)\\}(.*?)");
  private static final Pattern commonErrorPattern = Pattern.compile("^(.+?)[:;] (.+)$");

  private static final SecureRandom secureRandom = new SecureRandom();

  private final Map<String, String> properties;

  public EcdsaSigCallout(Map properties) {
    this.properties = CalloutUtil.genericizeMap(properties);
  }

  enum SignatureFormat {
    P1363,
    ASN1
  };

  enum CryptoAction {
    SIGN,
    VERIFY
  };

  enum EncodingType {
    NONE,
    BASE64,
    BASE64URL,
    BASE16
  };

  private static String varName(String s) {
    return varprefix + s;
  }

  private String resolveVariableReferences(String spec, MessageContext msgCtxt) {
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      String ref = matcher.group(2);
      String[] parts = ref.split(":", 2);
      Object v = msgCtxt.getVariable(parts[0]);
      if (v != null) {
        sb.append((String) v);
      } else if (parts.length > 1) {
        sb.append(parts[1]);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  private String getSourceVar() {
    String source = this.properties.get("source");
    if (source == null || source.equals("")) {
      // by default, get the content of the message (either request or response)
      return "message.content";
    }
    return source;
  }

  private String _getStringProp(MessageContext msgCtxt, String name, String defaultValue)
      throws Exception {
    String value = this.properties.get(name);
    if (value != null) value = value.trim();
    if (value == null || value.equals("")) {
      return defaultValue;
    }
    value = resolveVariableReferences(value, msgCtxt);
    if (value == null || value.equals("")) {
      throw new IllegalStateException(name + " resolves to null or empty.");
    }
    return value;
  }

  private EncodingType _getEncodingTypeProperty(MessageContext msgCtxt, String propName)
      throws Exception {
    return EncodingType.valueOf(_getStringProp(msgCtxt, propName, "NONE").toUpperCase());
  }

  private EncodingType getEncodeResult(MessageContext msgCtxt) throws Exception {
    return _getEncodingTypeProperty(msgCtxt, "encode-result");
  }

  private byte[] decodeString(String s, EncodingType decodingKind) throws Exception {
    if (decodingKind == EncodingType.BASE16) {
      return Base16.decode(s.replaceAll("-",""));
    }
    if (decodingKind == EncodingType.BASE64) {
      return Base64.getDecoder().decode(s);
    }
    if (decodingKind == EncodingType.BASE64URL) {
      return Base64.getUrlDecoder().decode(s);
    }
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private static CryptoAction findActionByName(String name) {
    for (CryptoAction action : CryptoAction.values()) {
      if (name.equals(action.name())) {
        return action;
      }
    }
    return null;
  }

  private CryptoAction getAction(MessageContext msgCtxt) throws Exception {
    String action = this.properties.get("action");
    if (action != null) action = action.trim();
    if (action == null || action.equals("")) {
      throw new IllegalStateException("specify an action.");
    }
    action = resolveVariableReferences(action, msgCtxt);

    CryptoAction cryptoAction = findActionByName(action.toUpperCase());
    if (cryptoAction == null) throw new IllegalStateException("specify a valid action.");

    return cryptoAction;
  }

  private static void toFixed(BigInteger x, byte[] a, int off, int len) throws Exception {
    byte[] t = x.toByteArray();
    if (t.length == len + 1 && t[0] == 0) System.arraycopy(t, 1, a, off, len);
    else if (t.length <= len) System.arraycopy(t, 0, a, off + len - t.length, t.length);
    else throw new Exception();
  }

  private static byte[] toP1363(byte[] asn1EncodedSignature) throws Exception {
    ASN1Sequence seq = ASN1Sequence.getInstance(asn1EncodedSignature);
    BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
    BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
    int n = (r.bitLength() + 7) / 8;
    // round up to nearest even integer
    n = (int) Math.round((n+1)/2) * 2;
    byte[] out = new byte[2 * n];
    toFixed(r, out, 0, n);
    toFixed(s, out, n, n);
    return out;
  }

  private static byte[] toASN1(byte[] p1363EncodedSignature) throws IOException {
    int n = p1363EncodedSignature.length / 2;
    BigInteger r = new BigInteger(+1, Arrays.copyOfRange(p1363EncodedSignature, 0, n));
    BigInteger s = new BigInteger(+1, Arrays.copyOfRange(p1363EncodedSignature, n, n * 2));
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new ASN1Integer(r));
    v.add(new ASN1Integer(s));
    return new DERSequence(v).getEncoded();
  }

  private SignatureFormat getFormat(MessageContext msgCtxt) throws Exception {
    String action = this.properties.get("format");
    if (action != null) action = action.trim();
    if (action == null || action.equals("")) {
      return SignatureFormat.ASN1;
    }
    action = resolveVariableReferences(action, msgCtxt);
    if (action.toUpperCase().equals("P1363")) {
      return SignatureFormat.P1363;
    }
    if (action.toUpperCase().equals("ASN1")) {
      return SignatureFormat.ASN1;
    }
    throw new IllegalStateException("specify a valid action.");
  }

  private ECPublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
    return (ECPublicKey) KeyUtil.decodePublicKey(_getRequiredString(msgCtxt, "public-key"));
  }

  private void emitKeyVariable(MessageContext msgCtxt, java.security.Key key, String label) {
    StringWriter sw = new StringWriter();
    try (PEMWriter pw = new PEMWriter(sw)) {
      pw.writeObject(key);
    } catch (IOException e) {
    }
    msgCtxt.setVariable(varName("output_" + label), sw.toString());
  }

  private ECPrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    boolean wantGenerateKey = _getBooleanProperty(msgCtxt, "generate-keypair", false);
    if (wantGenerateKey) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      String curve = _getStringProp(msgCtxt, "curve", "secp256r1");
      keyGen.initialize(new ECGenParameterSpec(curve), new SecureRandom());
      KeyPair pair = keyGen.generateKeyPair();
      ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();
      emitKeyVariable(msgCtxt, privateKey, "privatekey");
      emitKeyVariable(msgCtxt, pair.getPublic(), "publickey");
      return privateKey;
    }

    return (ECPrivateKey) KeyUtil.decodePrivateKey(
        _getRequiredString(msgCtxt, "private-key"),
        _getOptionalString(msgCtxt, "private-key-password"));
  }

  private String _getRequiredString(MessageContext msgCtxt, String name) throws Exception {
    String value = _getStringProp(msgCtxt, name, null);
    if (value == null)
      throw new IllegalStateException(String.format("%s resolves to null or empty.", name));
    return value;
  }

  private String _getOptionalString(MessageContext msgCtxt, String name) throws Exception {
    return _getStringProp(msgCtxt, name, null);
  }

  private boolean getDebug(MessageContext msgCtxt) throws Exception {
    return _getBooleanProperty(msgCtxt, "debug", false);
  }

  private boolean _getBooleanProperty(MessageContext msgCtxt, String propName, boolean defaultValue)
      throws Exception {
    String flag = this.properties.get(propName);
    if (flag != null) flag = flag.trim();
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    flag = resolveVariableReferences(flag, msgCtxt);
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    return flag.equalsIgnoreCase("TRUE");
  }

  private void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("action"));
  }

  private Function<byte[], Object> getEncoder(MessageContext msgCtxt) throws Exception {
    EncodingType encodingType = getEncodeResult(msgCtxt);
    if (encodingType == EncodingType.NONE) {
      // Emit the result as a Java byte array.
      // Will be retrievable only by another Java callout.
      msgCtxt.setVariable(varName("output_encoding"), "none");
      return (a) -> a; // nop
    }

    if (encodingType == EncodingType.BASE64) {
      msgCtxt.setVariable(varName("output_encoding"), "base64");
      return (a) -> Base64.getEncoder().encodeToString(a);
    }

    if (encodingType == EncodingType.BASE64URL) {
      msgCtxt.setVariable(varName("output_encoding"), "base64url");
      return (a) -> Base64.getUrlEncoder().encodeToString(a);
    }

    if (encodingType == EncodingType.BASE16) {
      msgCtxt.setVariable(varName("output_encoding"), "base16");
      return (a) -> Base16.encode(a);
    }

    throw new IllegalStateException("unhandled encoding");
  }

  private static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  private void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString().replaceAll("\n", " ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }

  protected byte[] getSignatureToVerify(MessageContext msgCtxt) throws Exception {
    String sigRep = _getRequiredString(msgCtxt, "signature");
    EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-signature");
    return decodeString(sigRep, decodingKind);
  }

  protected byte[] getSourceBytes(CryptoAction action, MessageContext msgCtxt) throws Exception {
    String sourceVar = getSourceVar();
    Object source1 = msgCtxt.getVariable(sourceVar);
    if (source1 == null) {
      throw new IllegalStateException(String.format("source '%s' resolves to null", sourceVar));
    }
    if (source1 instanceof byte[]) {
      return (byte[]) source1;
    }

    if (source1 instanceof String) {
      EncodingType decodingKind = _getEncodingTypeProperty(msgCtxt, "decode-source");
      return decodeString((String) source1, decodingKind);
    }

    // coerce and hope for the best
    return (source1.toString()).getBytes(StandardCharsets.UTF_8);
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = false;
    try {
      clearVariables(msgCtxt);
      debug = getDebug(msgCtxt);

      Signature sig = Signature.getInstance("SHA256withECDSA");
      CryptoAction action = getAction(msgCtxt); // sign or verify
      msgCtxt.setVariable(varName("action"), action.name().toLowerCase());
      byte[] source = getSourceBytes(action, msgCtxt);
      SignatureFormat format = getFormat(msgCtxt); // P1363 or ASN.1

      if (action == CryptoAction.SIGN) {
        ECPrivateKey privateKey = getPrivateKey(msgCtxt);
        sig.initSign(privateKey);
        sig.update(source);
        byte[] result = sig.sign();
        if (format == SignatureFormat.P1363) {
          result = toP1363(result);
        }
        msgCtxt.setVariable(varName("output_format"), format.toString());
        msgCtxt.setVariable(varName("signature"), getEncoder(msgCtxt).apply(result));
      } else if (action == CryptoAction.VERIFY) {
        msgCtxt.setVariable(varName("verified"), "false");
        ECPublicKey publicKey = getPublicKey(msgCtxt);
        sig.initVerify(publicKey);
        sig.update(source);
        byte[] signatureBytes = getSignatureToVerify(msgCtxt);
        if (format == SignatureFormat.P1363) {
          signatureBytes = toASN1(signatureBytes);
        }
        msgCtxt.setVariable(varName("input_format"), format.toString());
        boolean verified = sig.verify(signatureBytes);
        if (!verified) {
          msgCtxt.setVariable(varName("error"), "verification of the signature failed.");
          return ExecutionResult.ABORT;
        } else {
          msgCtxt.setVariable(varName("verified"), "true");
        }
      } else {
        msgCtxt.setVariable(varName("error"), "invalid action");
        return ExecutionResult.ABORT;
      }
    } catch (Exception e) {
      if (debug) {
        e.printStackTrace();
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
