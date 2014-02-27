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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * An abstract base for password encryption that uses one of the SHA-2 
 * variants (e.g. SHA-256).
 *
 * @author Carl Harris
 */
abstract class Sha2Crypt extends Crypt {

  private static final String ROUNDS_PARAM = "rounds=";
  private static final int MIN_ROUNDS = 1000;
  private static final int MAX_ROUNDS = 999999999; 
  private static final int DEFAULT_ROUNDS = 5000;
  private static final int MAX_SALT_LENGTH = 16;
  
  /**
   * Constructs a new instance.
   * @param type
   */
  protected Sha2Crypt(Type type) {
    super(type);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected String doCrypt(Password password, Salt salt) 
      throws NoSuchAlgorithmException, UnsupportedEncodingException {
    
    Integer rounds = rounds(salt);
    byte[] encrypted = doCrypt(password.getBytes(CHARACTER_ENCODING), 
        salt.getBytes(MAX_SALT_LENGTH, CHARACTER_ENCODING),
        rounds == null ? DEFAULT_ROUNDS : rounds);
    
    return passwordToString(encrypted, salt, MAX_SALT_LENGTH, rounds);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected String encodeParameters(Object... params) {
    if (params[0] == null) return null;
    return ROUNDS_PARAM + params[0];
  }

  /**
   * Gets the number of rounds explicitly requested in the given salt
   * @param salt the subject salt
   * @return number of rounds requested or {@code null} if the salt does not
   *    specify the number of rounds
   */
  private Integer rounds(Salt salt) {
    String params = salt.getParams();
    if (params == null || !params.startsWith(ROUNDS_PARAM)) return null;  
    Integer rounds = Integer.valueOf(params.substring(ROUNDS_PARAM.length()));
    rounds = Math.max(MIN_ROUNDS, rounds);
    rounds = Math.min(rounds, MAX_ROUNDS);
    return rounds;
  }
  
  /**
   * Encrypts the given password.
   * @param password the password to encrypt
   * @param salt salt for the encryption
   * @param rounds number of rounds requested
   * @return
   * @throws NoSuchAlgorithmException
   */
  private byte[] doCrypt(byte[] password, byte[] salt, int rounds)
      throws NoSuchAlgorithmException {
    
    /* 1. start digest A */
    final MessageDigest a = type.newDigest();
    final int digestLength = a.getDigestLength();
    
    /* 2. the password string is added to digest A  */
    a.update(password);

    /* 3.  the salt string is added to digest A */
    a.update(salt);
    
    /* 4.  start digest B */
    final MessageDigest b = type.newDigest();
    
    /* 5.  add the password to digest B */    
    b.update(password);
    
    /* 6.  add the salt string to digest B */
    b.update(salt);
    
    /* 7.  add the password again to digest B */    
    b.update(password);
    
    /* 8.  finish digest B */
    final byte[] sumB = b.digest();
    
    /* 9.  For each block of 32 or 64 bytes in the password string 
     *     add digest B to digest A
     */
    for (int i = 0, max = password.length / digestLength; i < max; i++) {
      a.update(sumB);
    }
    
    /* 10. For the remaining N bytes of the password string add the first
     *     N bytes of digest B to digest A 
     */
    a.update(sumB, 0, password.length % digestLength);
    
    /* 11. For each bit of the binary representation of the length of the
     *     password string up to and including the highest 1-digit, starting
     *     from to lowest bit position (numeric value 1):
     *     a) for a 1-digit add digest B to digest A
     *     b) for a 0-digit add the password string
     */    
    for (int length = password.length; length > 0; length >>>= 1) {
      if ((length & 1) != 0) {
        a.update(sumB);
      }
      else {
        a.update(password);
      }
    }
    
    /* 12. finish digest A */
    final byte[] sumA = a.digest();
    
    /* 13. start digest DP */
    final MessageDigest dp = type.newDigest();
    
    /* 14. for every byte in the password add the password to digest DP */
    for (int i = 0; i < password.length; i++) {
      dp.update(password);
    }
    
    /* 15. finish digest DP */
    final byte[] sumDP = dp.digest();
    
    /* 16. produce byte sequence P of the same length as the password where
     *     a) for each block of 32 or 64 bytes of length of the password string
     *        the entire digest DP is used
     *     b) for the remaining N (up to  31 or 63) bytes use the first N
     *        bytes of digest DP 
     */
    byte[] seqP = makeSequence(sumDP, password.length, digestLength);

    /* 17. start digest DS */
    final MessageDigest ds = type.newDigest();
    
    /* 18. repeat the following 16+A[0] times, where A[0] represents the first
     *     byte in digest A interpreted as an 8-bit unsigned value:
     *     add the salt to digest DS  
     */
    for (int i = 0, max = 16 + ((int) sumA[0] & 0xff); i < max; i++) {
      ds.update(salt);
    }

    /* 19. finish digest DS */
    final byte[] sumDS = ds.digest();

    /* 20. produce byte sequence S of the same length as the salt string where
     *     a) for each block of 32 or 64 bytes of length of the salt string
     *        the entire digest DS is used
     *     b) for the remaining N (up to  31 or 63) bytes use the first N
     *        bytes of digest DS
     */
    final byte[] seqS = makeSequence(sumDS, salt.length, digestLength);

    /* 21. repeat a loop according to the number specified in the rounds=<N>
     *     specification in the salt (or the default value if none is
     *     present).  Each round is numbered, starting with 0 and up to N-1.
     *
     *     The loop uses a digest as input.  In the first round it is the
     *     digest produced in step 12.  In the latter steps it is the digest
     *     produced in step 21.h.  The following text uses the notation
     *     "digest A/C" to describe this behavior.
     */
    
    byte[] ac = sumA;
    
    for (int i = 0, max = rounds; i < max; i++) {
      /* a) start digest C */
      final MessageDigest c = type.newDigest();
      
      if (i % 2 != 0) {
        /* b) for odd round numbers add the byte sequence P to digest C */
        c.update(seqP);
      }
      else {
        /* c) for even round numbers add digest A/C */
        c.update(ac);
      }
      
      if (i % 3 != 0) {
        /* d) for all round numbers not divisible by 3 add the byte sequence S */
        c.update(seqS);
      }
      
      if (i % 7 != 0) {
        /* e) for all round numbers not divisible by 7 add the byte sequence P */
        c.update(seqP);
      }
      
      if (i % 2 != 0) {
        /* f) for odd round numbers add digest A/C */
        c.update(ac);
      }
      else {
        /* g) for even round numbers add the byte sequence P */
        c.update(seqP);
      }
      
      /* h) finish digest C */
      ac = c.digest();
    }
    return ac;
  }

  /**
   * Makes a sequence as described as steps 16 and 20 of the algorithm.
   * @param sum the intermediate sum to place into the sequence
   * @param length length of the sequence in bytes
   * @param digestLength length of the digest in bytes
   * @return sequence
   */
  private byte[] makeSequence(byte[] sum, int length,
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

}
