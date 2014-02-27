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
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

/**
 * A wrapper for a character array containing a password.
 *
 * @author Carl Harris
 */
class Password {

  private final char[] text;
  
  /**
   * Constructs a new instance.
   * @param text
   */
  public Password(char[] text) {
    this.text = text.clone();
  }
  
  /**
   * Gets the text of the password.
   * @return
   */
  public char[] getText() {
    return text;
  }
  
  /**
   * Clears the buffer containing the password.
   */
  public void clear() {
    for (int i = 0; i < text.length; i++) {
      text[i] = 0;
    }
  }
  
  /**
   * Gets the password as an array of bytes of a given character encoding.
   * @param charset character set name
   * @return byte array
   * @throws UnsupportedEncodingException
   */
  public byte[] getBytes(String charset) throws UnsupportedEncodingException {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      Writer writer = new OutputStreamWriter(outputStream, charset);
      writer.write(text);
      writer.close();
      return outputStream.toByteArray();
    }
    catch (UnsupportedEncodingException ex) {
      throw ex;
    }
    catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }
  
}
