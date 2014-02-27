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

/**
 * A base-64 encoder.
 *
 * @author Carl Harris
 */
class Base64 {

  private static final String BASE64_SET = 
      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  /**
   * Encodes a 24-bit value as a character array containing base 64.
   * @param b2 high-order 8 bits
   * @param b1 middle 8 bits
   * @param b0 low-order 8 bits
   * @param n number of characters to encode
   * @return character array of length {@code n} containing the base 64 
   *    representation of the input value
   */
  public static char[] encode(byte b2, byte b1, byte b0, int n) {
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

}
