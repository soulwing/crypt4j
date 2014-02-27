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
 * A SHA-256 crypt implementation.
 *
 * @author Carl Harris
 */
class Sha256Crypt extends Sha2Crypt {

  /**
   * Constructs a new instance.
   * @param type
   */
  public Sha256Crypt(Type type) {
    super(type);
  }
  
  /**
   * {@inheritDoc}
   */
  @Override
  protected String encodePassword(byte[] password) {
    StringBuilder sb = new StringBuilder();
    sb.append(Base64.encode(password[0], password[10], password[20], 4));
    sb.append(Base64.encode(password[21], password[1], password[11], 4));
    sb.append(Base64.encode(password[12], password[22], password[2], 4));
    sb.append(Base64.encode(password[3], password[13], password[23], 4));
    sb.append(Base64.encode(password[24], password[4], password[14], 4));
    sb.append(Base64.encode(password[15], password[25], password[5], 4));
    sb.append(Base64.encode(password[6], password[16], password[26], 4));
    sb.append(Base64.encode(password[27], password[7], password[17], 4));
    sb.append(Base64.encode(password[18], password[28], password[8], 4));
    sb.append(Base64.encode(password[9], password[19], password[29], 4));
    sb.append(Base64.encode((byte) 0, password[31], password[30], 3));
    return sb.toString();
  }

}
