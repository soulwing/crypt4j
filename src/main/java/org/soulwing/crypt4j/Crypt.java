/*
 * File created on Feb 27, 2014 
 *
 * Copyright (c) 2014 Carl Harris, Jr.
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

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;

/**
 * A utility class that encrypts password strings using algorithms that 
 * are compatible with {@code crypt(3)} from the GNU C library.
 *
 * @author Carl Harris
 */
public abstract class Crypt {
  
  public static final String CHARACTER_ENCODING = "UTF-8";
  
  protected final Type type;
  
  /**
   * Constructs a new instance.
   * @param type
   */
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
    String encrypted = Crypt.newInstance(Type.forSalt(s)).doCrypt(p, s);
    p.clear();
    return encrypted;
  }

  /**
   * Constructs a new instance of the specified type.
   * @param type crypt type
   * @return new crypt object
   */
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
  
  /**
   * Performs the password encryption operation.
   * @param password the password to encrypt
   * @param salt salt for the encryption
   * @return formatted crypt output string
   * @throws NoSuchAlgorithmException if the specified encryption type cannot
   *    be supported on the platform
   * @throws UnsupportedEncodingException if the password character encoding
   *    cannot be supported on the platform
   */
  protected abstract String doCrypt(Password password, Salt salt)
      throws NoSuchAlgorithmException, UnsupportedEncodingException;
  
  /**
   * Converts the encrypted password to a crypt output string.
   * @param password the encrypted password
   * @param salt salt
   * @param maxSaltLength maximum allowable length for the salt
   * @param params subclass-specific parameters (these will be passed to
   *    {@link #encodeParameters(Object...)}
   * @return crypt output string
   */
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

  /**
   * Encodes the parameters specified with the salt in the crypt output
   * string.
   * @param params the subclass-specific parameters provided to
   *    {@link #passwordToString(byte[], Salt, int, Object...)}
   * @return string encoding of parameters or {@code null} to indicate that
   *    no parameters are needed in the ouptut string
   */
  protected String encodeParameters(Object... params) {
    throw new UnsupportedOperationException();
  }

  /**
   * Encodes the password for use in the crypt output string.
   * @param password the password to encode
   * @return string encoding of {@code password}
   */
  protected abstract String encodePassword(byte[] password);

}
