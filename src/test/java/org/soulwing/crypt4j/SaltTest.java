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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.Test;

/**
 * Unit tests for {@link Salt}.
 *
 * @author Carl Harris
 */
public class SaltTest {

  @Test
  public void testUntyped() throws Exception {
    Salt salt = new Salt("aSalt");
    assertThat(salt.getText(), is(equalTo("aSalt")));
    assertThat(salt.getType(), is(equalTo(0)));
    assertThat(salt.getParams(), is(nullValue()));
  }

  @Test
  public void testTypedWithNoParams() throws Exception {
    Salt salt = new Salt("$1$aSalt");
    assertThat(salt.getText(), is(equalTo("aSalt")));
    assertThat(salt.getType(), is(equalTo(1)));
    assertThat(salt.getParams(), is(nullValue()));
  }

  @Test
  public void testTypedWithParams() throws Exception {
    Salt salt = new Salt("$1$params$aSalt");
    assertThat(salt.getText(), is(equalTo("aSalt")));
    assertThat(salt.getType(), is(equalTo(1)));
    assertThat(salt.getParams(), is(equalTo("params")));
  }

}
