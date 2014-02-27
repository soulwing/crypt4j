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
 * A SHA-512 crypt implementation.
 *
 * @author Carl Harris
 */
class Sha512Crypt extends Sha2Crypt {

  /**
   * Constructs a new instance.
   * @param type
   */
  public Sha512Crypt(Type type) {
    super(type);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected String encodePassword(byte[] password) {
    StringBuilder sb = new StringBuilder();
    sb.append(Base64.encode(password[0], password[21], password[42], 4));
    sb.append(Base64.encode(password[22], password[43], password[1], 4));
    sb.append(Base64.encode(password[44], password[2], password[23], 4));
    sb.append(Base64.encode(password[3], password[24], password[45], 4));
    sb.append(Base64.encode(password[25], password[46], password[4], 4));
    sb.append(Base64.encode(password[47], password[5], password[26], 4));
    sb.append(Base64.encode(password[6], password[27], password[48], 4));
    sb.append(Base64.encode(password[28], password[49], password[7], 4));
    sb.append(Base64.encode(password[50], password[8], password[29], 4));
    sb.append(Base64.encode(password[9], password[30], password[51], 4));
    sb.append(Base64.encode(password[31], password[52], password[10], 4));
    sb.append(Base64.encode(password[53], password[11], password[32], 4));
    sb.append(Base64.encode(password[12], password[33], password[54], 4));
    sb.append(Base64.encode(password[34], password[55], password[13], 4));
    sb.append(Base64.encode(password[56], password[14], password[35], 4));
    sb.append(Base64.encode(password[15], password[36], password[57], 4));
    sb.append(Base64.encode(password[37], password[58], password[16], 4));
    sb.append(Base64.encode(password[59], password[17], password[38], 4));
    sb.append(Base64.encode(password[18], password[39], password[60], 4));
    sb.append(Base64.encode(password[40], password[61], password[19], 4));
    sb.append(Base64.encode(password[62], password[20], password[41], 4));
    sb.append(Base64.encode((byte) 0, (byte) 0, password[63], 2));
    return sb.toString();
  }
  
  

}
