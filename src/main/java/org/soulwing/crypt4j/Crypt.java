/*
 * File created on Feb 27, 2014 
 *
 * Copyright (c) 2014 Virginia Polytechnic Institute and State University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.soulwing.crypt4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;

/**
 * 
 *
 * @author Carl Harris
 */
public abstract class Crypt {
  
  public static final String CHARACTER_ENCODING = "UTF-8";
  
  private static final String BASE64_SET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  
  protected final Type type;
  
  protected Crypt(Type type) {
    this.type = type;
  }
  
  /**
   * Encrypts (digests) the given password using the algorithm identified
   * by the given salt.
   * @param password the password to encrypt
   * @param salt algorithm identifier, parameters, and salt text
   * @return the encrypted (digested) password
   * @throws NoSuchAlgorithmException if the desired algorithm is not 
   *    supported on this platform
   * @throws UnsupportedEncodingException if UTF-8 encoding is not available
   *    not the platform
   *
   */
  public static String crypt(char[] password, String salt) 
      throws NoSuchAlgorithmException, UnsupportedEncodingException {
    Salt s = new Salt(salt);
    Password p = new Password(password);
    return Crypt.newInstance(Type.forSalt(s)).doCrypt(p, s);
  }

  private static Crypt newInstance(Type type) 
      throws NoSuchAlgorithmException {
    try {
      Constructor<? extends Crypt> constructor = 
          type.providerClass.getConstructor(Type.class);
      return constructor.newInstance(type);
    }
    catch (NoSuchMethodException ex) {
      throw new RuntimeException(ex);
    }
    catch (IllegalAccessException ex) {
      throw new RuntimeException(ex);
    }
    catch (InvocationTargetException ex) {
      throw new RuntimeException(ex);
    }
    catch (InstantiationException ex) {
      throw new RuntimeException(ex);
    }
  }
  
  protected abstract String doCrypt(Password password, Salt salt)
      throws NoSuchAlgorithmException, UnsupportedEncodingException;
  
  protected byte[] makeSequence(byte[] sum, int length,
      final int digestLength) {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      for (int i = 0, max = length / digestLength; i < max; i++) {
        outputStream.write(sum);
      }
      outputStream.write(sum, 0, length % digestLength);
      return outputStream.toByteArray();
    }
    catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }
  
  protected char[] toBase64(byte b2, byte b1, byte b0, int n) {
    char[] buf = new char[n];
    int i = 0;
    int w = (((int) b2 & 0xff) << 16) 
          | (((int) b1 & 0xff) << 8) 
          | ((int) b0 & 0xff);
    
    while (i < n) {
      buf[i++] = BASE64_SET.charAt(w & 0x3f);
      w >>>= 6;
    }
    return buf;
  }
  
  protected String passwordToString(byte[] password, Salt salt, 
      int maxSaltLength, Object... params) {
    StringBuilder sb = new StringBuilder();
    if (salt.getType() == 0) {
      return encodePassword(password);
    }
    sb.append('$').append(salt.getType()).append('$');
    if (params != null && params.length != 0) {
      String encodedParameters = encodeParameters(params);
      if (encodedParameters != null) {
        sb.append(encodedParameters).append('$');
      }
    }
    sb.append(salt.getText(maxSaltLength)).append('$');
    sb.append(encodePassword(password));
    return sb.toString();
  }

  protected String encodeParameters(Object... params) {
    throw new UnsupportedOperationException();
  }

  protected abstract String encodePassword(byte[] password);

  public static void main(String[] args) throws Exception {
    System.out.println(
        Crypt.crypt("Hello world!".toCharArray(), "$6$rounds=10000$saltstring"));
  }
}
