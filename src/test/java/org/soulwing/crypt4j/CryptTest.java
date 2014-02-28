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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import org.junit.Test;

/**
 * Tests for {@link Crypt}.
 *
 * @author Carl Harris
 */
public class CryptTest {

  @Test(expected = NoSuchAlgorithmException.class)
  public void testWithNonExistentType() throws Exception {
    Crypt.crypt("password".toCharArray(), "$99$XX");
  }
  
  @Test
  public void runTestCases() throws Exception {
    Properties properties = loadTestCases();
    int i = 0;
    while (properties.containsKey(i + ".password")) {
      String password = properties.getProperty(i + ".password");
      String salt = properties.getProperty(i + ".salt");
      String expected = properties.getProperty(i + ".expected");
      String note = properties.getProperty(i + ".note");
      String actual = Crypt.crypt(password.toCharArray(), salt);
      System.out.println((actual.equals(expected) ? "OK" : "FAIL")
          + ": " + note);
      
      assertThat("failed: " + note, actual, is(equalTo(expected)));
      i++;
    }
  }
  
  private Properties loadTestCases() throws Exception {
    try (InputStream inputStream = openTestCases()) {
      Properties properties = new Properties();
      properties.load(inputStream);
      return properties;
    }
  }
  
  private InputStream openTestCases() throws Exception {
    InputStream inputStream = getClass().getResourceAsStream(
        getClass().getSimpleName() + ".properties");
    if (inputStream == null) {
      throw new FileNotFoundException();
    }
    return inputStream;
  }
}
