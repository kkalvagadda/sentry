/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.sentry.sentryexoprter;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class SentryExporterTest {
  @Before
  public void setUp() throws Exception {
   }

  @After
  public void tearDown() throws Exception {

  }

 @Test
  public void testExecute() throws Exception {
   String[] args = new String[3];
   args[0] = "-m ";
   args[1] = "-s sentry-site.xml";
   args[2] = "-r ranger-hive-security.xml";
   SentryExporter exporter = new SentryExporter(args);
   exporter.setRangerConfig("/Users/kkalyan/source_repo/maven_sentry/sentry_cdh/sentry/ranger-export/src/main/resources/ranger-hive-security.xml");
   exporter.setSentryConfig("/Users/kkalyan/source_repo/maven_sentry/sentry_cdh/sentry/ranger-export/src/main/resources/sentry-site.xml");
   //validate sentry configuration
   Assert.assertNotNull(exporter.sentryConfig);
   //validate ranger configuration
   Assert.assertNotNull(exporter.rangerConfig);

   exporter.execute();
 }
}