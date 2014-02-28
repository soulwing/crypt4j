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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * An MD5 crypt implementation.
 *
 * @author Carl Harris
 */
class Md5Crypt extends Crypt {

  private static final String SALT_PREFIX = "$1$";
  private static final int MAX_SALT_LENGTH = 8;
  private static final int ROUNDS = 1000;
  
  /**
   * Constructs a new instance.
   * @param type
   */
  public Md5Crypt(Type type) {
    super(type);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected String doCrypt(Password password, Salt salt)
      throws NoSuchAlgorithmException, UnsupportedEncodingException {
    byte[] encrypted = doCrypt(password.getBytes(CHARACTER_ENCODING), 
        salt.getBytes(MAX_SALT_LENGTH, CHARACTER_ENCODING));
    
    return passwordToString(encrypted, salt, MAX_SALT_LENGTH);
  }

  private byte[] doCrypt(byte[] password, byte[] salt) 
      throws NoSuchAlgorithmException, UnsupportedEncodingException {

    /* start digest A */
    final MessageDigest a = type.newDigest();
    final int digestLength = a.getDigestLength();
    
    /* add the key string */
    a.update(password);
    
    /* Because the SALT argument need not always have the salt prefix we
     * add it separately.
     */
    a.update(SALT_PREFIX.getBytes(CHARACTER_ENCODING));
    
    /* The last part is the salt string. */
    a.update(salt);
    
    /* Compute alternate MD5 sum with input KEY, SALT, and KEY. */
    final MessageDigest b = type.newDigest();
    
    /* Add the key */
    b.update(password);
    
    /* Add the salt */
    b.update(salt);
    
    /* Add the key again */
    b.update(password);
    
    /* Get alternate sum */
    final byte[] sumB = b.digest();
    
    /* Add for any character in the key one byte of the alternate sum.  */
    for (int i = 0, max = password.length / digestLength; i < max; i++) {
      a.update(sumB);
    }
    a.update(sumB, 0, password.length % digestLength);
    
    /* The original implementation now does something weird: for every 1
     * bit in the key the first 0 is added to the buffer, for every 0 bit 
     * the first character of the key.  This does not seem to be what was 
     * intended but we have to follow this to be compatible.  
     */
    final byte[] zero = new byte[] { 0 };
    for (int length = password.length; length != 0; length >>>= 1) {
      if ((length & 1) != 0) {
        a.update(zero);
      }
      else {
        a.update(password, 0, 1);
      }
    }
    
    /* Create intermediate result. */
    final byte[] sumA = a.digest();
    
    /* loop which just processes the output of each round to increase 
     * computational costs  
     */    
    byte[] ac = sumA;
    for (int i = 0; i < ROUNDS; i++) {
      final MessageDigest c = type.newDigest();
      
      if (i % 2 != 0) {
        /* for all odd rounds add in key */
        c.update(password);
      }
      else {
        /* for all even rounds add in result of previous round */
        c.update(ac);
      }
      
      /* for all rounds not divisible by 3, add in salt */
      if (i % 3 != 0) {
        c.update(salt);
      }
      
      /* for all rounds not divisible by 7, add in key */ 
      if (i % 7 != 0) {
        c.update(password);
      }
      
      if (i % 2 != 0) {
        /* for all odd rounds add in result of previous round */
        c.update(ac);
      }
      else {
        /* for all even rounds add in password */
        c.update(password);
      }

      /* Create intermediate result */
      ac = c.digest();
    }
    
    return ac;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected String encodePassword(byte[] password) {
    StringBuilder sb = new StringBuilder();
    sb.append(Base64.encode(password[0], password[6], password[12], 4));
    sb.append(Base64.encode(password[1], password[7], password[13], 4));
    sb.append(Base64.encode(password[2], password[8], password[14], 4));
    sb.append(Base64.encode(password[3], password[9], password[15], 4));
    sb.append(Base64.encode(password[4], password[10], password[5], 4));
    sb.append(Base64.encode((byte) 0, (byte) 0, password[11], 2));
    return sb.toString();
  }

}
