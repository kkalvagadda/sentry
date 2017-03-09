/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sentry.hdfs;

import static org.apache.sentry.hdfs.Updateable.Update;

/**
 * ImageRetriever obtains a complete snapshot of either Sentry Permissions
 * ({@code PermissionsUpdate}) or Sentry representation of Hive Paths
 * ({@code PathsUpdate}).
 * <p>
 * The snapshot image should represent a consistent state.
 * The {@link #retrieveFullImage(long)} method obtains such state snapshot from
 * a persistent storage.
 * The Snapshots are propagated to a consumer of Sentry, such as HDFS NameNode,
 * whenever the consumer needs to synchronize its full state.
 */
public interface ImageRetriever<K extends Update> {

  /**
   * Retrieve a complete snapshot of type {@code Update} from a persistent storage.
   *
   * @param seqNum
   * @return a complete snapshot of type {@link Update}, e.g {@link PermissionsUpdate}
   *         or {@link PathsUpdate}
   * @throws Exception
   */
  K retrieveFullImage(long seqNum) throws Exception;

}