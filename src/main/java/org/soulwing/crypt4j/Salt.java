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
 * A value holder for salt string.
 *
 * @author Carl Harris
 */
class Salt {

  private final int type;
  private final String params;
  private final String text;
  
  public Salt(String salt) {
    if (salt.charAt(0) != '$') {
      this.type = 0;
      this.params = null;
      this.text = salt;
      return;
    }
    
    int index = 1;
    int extent = salt.indexOf('$', index);
    if (extent == -1) {
      throw new IllegalArgumentException("illegal salt format");
    }
    this.type = Integer.parseInt(salt.substring(index, extent));
    
    index = extent + 1;
    if (index > salt.length()) {
      throw new IllegalArgumentException("illegal salt format");
    }
    
    extent = salt.indexOf('$', index);
    if (extent == -1) {
      this.params = null;
    }
    else {
      this.params = salt.substring(index, extent);
      index = extent + 1;
      if (index > salt.length()) {
        throw new IllegalArgumentException("illegal salt format");
      }
    }
    
    this.text = salt.substring(index, salt.length());
  }

  /**
   * Gets the {@code type} property.
   * @return
   */
  public int getType() {
    return type;
  }

  /**
   * Gets the {@code params} property.
   * @return
   */
  public String getParams() {
    return params;
  }

  /**
   * Gets the {@code text} property.
   * @return
   */
  public String getText() {
    return text;
  }

  /**
   * Gets the salt text truncated to a given maximum length.
   * @param maxLength maximum length
   * @return truncated salt text
   */
  public String getText(int maxLength) {
    return text.substring(0, Math.min(text.length(), maxLength));
  }
  
  /**
   * Gets the salt text as an array of bytes of a given character encoding.
   * @param charset character set name
   * @return byte array
   * @throws UnsupportedEncodingException
   */
  public byte[] getBytes(int maxLength, String charset) 
      throws UnsupportedEncodingException {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      Writer writer = new OutputStreamWriter(outputStream, charset);
      writer.write(text, 0, Math.min(text.length(), maxLength));
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
