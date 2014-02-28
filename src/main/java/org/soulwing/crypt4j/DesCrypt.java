/*
 * File created on Feb 28, 2014 
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

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.digest.UnixCrypt;

/**
 * A DES crypt implementation that simply delegates to the implementation
 * in Commons Codec.
 *
 * @author Carl Harris
 */
class DesCrypt extends Crypt {

  private static final String UNIX_CRYPT_CLASS = 
      "org.apache.commons.codec.digest.UnixCrypt";
  
  /**
   * Constructs a new instance.
   * @param type
   */
  public DesCrypt(Type type) {
    super(type);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected String doCrypt(Password password, Salt salt)
      throws NoSuchAlgorithmException, UnsupportedEncodingException {
    checkUnixCryptAvailability();
    return UnixCrypt.crypt(password.getBytes(CHARACTER_ENCODING), 
        salt.getText(2));
  }

  private void checkUnixCryptAvailability() 
      throws NoSuchAlgorithmException {
    try {
      getClassLoader().loadClass(UNIX_CRYPT_CLASS);
    }
    catch (ClassNotFoundException ex) {
      throw new NoSuchAlgorithmException(
          "DES unavailable; Commons Codec library not on classpath");
    }
  }
  
  private ClassLoader getClassLoader() {
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    if (classLoader == null) {
      classLoader = getClass().getClassLoader();
    }
    return classLoader;
  }
  
  /**
   * {@inheritDoc}
   */
  @Override
  protected String encodePassword(byte[] password) {
    throw new UnsupportedOperationException();
  }

}
