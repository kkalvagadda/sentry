/**
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

package org.apache.sentry.provider.db.service.persistent;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.collect.Lists;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.alias.UserProvider;
import org.apache.sentry.SentryOwnerInfo;
import org.apache.sentry.api.common.ApiConstants.PrivilegeScope;
import org.apache.sentry.api.service.thrift.*;
import org.apache.sentry.core.common.exception.SentryAccessDeniedException;
import org.apache.sentry.core.common.exception.SentryInvalidInputException;
import org.apache.sentry.core.common.utils.SentryConstants;
import org.apache.sentry.core.model.db.AccessConstants;
import org.apache.sentry.core.common.exception.SentryAlreadyExistsException;
import org.apache.sentry.core.common.exception.SentryNoSuchObjectException;
import org.apache.sentry.hdfs.PathsUpdate;
import org.apache.sentry.hdfs.PermissionsUpdate;
import org.apache.sentry.hdfs.UniquePathsUpdate;
import org.apache.sentry.hdfs.Updateable;
import org.apache.sentry.hdfs.service.thrift.TPathEntry;
import org.apache.sentry.hdfs.service.thrift.TPathsDump;
import org.apache.sentry.hdfs.service.thrift.TPathsUpdate;
import org.apache.sentry.hdfs.service.thrift.TPrivilegeChanges;
import org.apache.sentry.hdfs.service.thrift.TPrivilegePrincipal;
import org.apache.sentry.hdfs.service.thrift.TPrivilegePrincipalType;
import org.apache.sentry.hdfs.service.thrift.TRoleChanges;
import org.apache.sentry.provider.db.service.model.MSentryPermChange;
import org.apache.sentry.provider.db.service.model.MSentryPathChange;
import org.apache.sentry.provider.db.service.model.MSentryPrivilege;
import org.apache.sentry.provider.db.service.model.MSentryRole;
import org.apache.sentry.provider.db.service.model.MPath;
import org.apache.sentry.provider.db.service.model.MSentryUser;
import org.apache.sentry.provider.file.PolicyFile;
import org.apache.sentry.api.common.SentryServiceUtil;
import org.apache.sentry.service.common.ServiceConstants;
import org.apache.sentry.service.common.ServiceConstants.SentryPrincipalType;
import org.apache.sentry.service.common.ServiceConstants.ServerConfig;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.io.Files;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.sentry.provider.db.service.persistent.QueryParamBuilder.newQueryParamBuilder;

import javax.jdo.JDODataStoreException;

public class TestSentryStore extends org.junit.Assert {

  private static final Logger LOGGER = LoggerFactory.getLogger(TestSentryStore.class);

  private static File dataDir;
  private static SentryStore sentryStore;
  private static String[] adminGroups = { "adminGroup1" };
  private static PolicyFile policyFile;
  private static File policyFilePath;
  final long NUM_PRIVS = 5;  // > SentryStore.PrivCleaner.NOTIFY_THRESHOLD
  private static Configuration conf = null;
  private static char[] passwd = new char[] { '1', '2', '3'};

  @BeforeClass
  public static void setup() throws Exception {
    conf = new Configuration(true);
    final String ourUrl = UserProvider.SCHEME_NAME + ":///";
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, ourUrl);

    // enable HDFS sync, so perm and path changes will be saved into DB
    conf.set(ServiceConstants.ServerConfig.PROCESSOR_FACTORIES, "org.apache.sentry.hdfs.SentryHDFSServiceProcessorFactory");
    conf.set(ServiceConstants.ServerConfig.SENTRY_POLICY_STORE_PLUGINS, "org.apache.sentry.hdfs.SentryPlugin");

    // THis should be a UserGroupInformation provider
    CredentialProvider provider = CredentialProviderFactory.getProviders(conf).get(0);


    // The user credentials are stored as a static variable by UserGrouoInformation provider.
    // We need to only set the password the first time, an attempt to set it for the second
    // time fails with an exception.
    if(provider.getCredentialEntry(ServerConfig.SENTRY_STORE_JDBC_PASS) == null) {
      provider.createCredentialEntry(ServerConfig.SENTRY_STORE_JDBC_PASS, passwd);
      provider.flush();
    }

    dataDir = new File(Files.createTempDir(), "sentry_policy_db");
    conf.set(ServerConfig.SENTRY_VERIFY_SCHEM_VERSION, "false");
    conf.set(ServerConfig.SENTRY_STORE_JDBC_URL,
        "jdbc:derby:;databaseName=" + dataDir.getPath() + ";create=true");
    conf.set(ServerConfig.SENTRY_STORE_JDBC_PASS, "dummy");
    conf.setStrings(ServerConfig.ADMIN_GROUPS, adminGroups);
    conf.set(ServerConfig.SENTRY_STORE_GROUP_MAPPING,
        ServerConfig.SENTRY_STORE_LOCAL_GROUP_MAPPING);
    policyFilePath = new File(dataDir, "local_policy_file.ini");
    conf.set(ServerConfig.SENTRY_STORE_GROUP_MAPPING_RESOURCE,
        policyFilePath.getPath());

    // These tests do not need to retry transactions, so setting to 1 to reduce testing time
    conf.setInt(ServerConfig.SENTRY_STORE_TRANSACTION_RETRY, 1);

    // SentryStore should be initialized only once. The tables created by the test cases will
    // be cleaned up during the @After method.
    sentryStore = new SentryStore(conf);

    boolean hdfsSyncEnabled = SentryServiceUtil.isHDFSSyncEnabled(conf);
    sentryStore.setPersistUpdateDeltas(hdfsSyncEnabled);
  }

  @Before
  public void before() throws Exception {
    policyFile = new PolicyFile();
    String adminUser = "g1";
    addGroupsToUser(adminUser, adminGroups);
    writePolicyFile();
  }

  @After
  public void after() {
    sentryStore.clearAllTables();
  }

  @AfterClass
  public static void teardown() {
    if (dataDir != null) {
      FileUtils.deleteQuietly(dataDir);
    }

    sentryStore.stop();
  }

  /**
   * Fail test if role already exists
   * @param roleName Role name to checl
   * @throws Exception
   */
  private void checkRoleDoesNotExist(String roleName) throws Exception {
    try {
      sentryStore.getMSentryRoleByName(roleName);
      fail("Role " + roleName + "already exists");
    } catch (SentryNoSuchObjectException e) {
      // Ok
    }
  }

  /**
   * Fail test if role doesn't exist
   * @param roleName Role name to checl
   * @throws Exception
   */
  private void checkRoleExists(String roleName) throws Exception {
    assertEquals(roleName.toLowerCase(),
            sentryStore.getMSentryRoleByName(roleName).getRoleName());
  }

  /**
   * Create a role with the given name and verify that it is created
   * @param roleName
   * @throws Exception
   */
  private void createRole(String roleName) throws Exception {
    checkRoleDoesNotExist(roleName);
    sentryStore.createSentryRole(roleName);
    checkRoleExists(roleName);
  }

  @Test
  public void testCredentialProvider() throws Exception {
    assertArrayEquals(passwd, conf.getPassword(ServerConfig.
        SENTRY_STORE_JDBC_PASS));
  }

  @Test
  public void testCaseInsensitiveRole() throws Exception {
    String roleName = "newRole";
    String grantor = "g1";
    Set<TSentryGroup> groups = Sets.newHashSet();
    TSentryGroup group = new TSentryGroup();
    group.setGroupName("test-groups-g1");
    groups.add(group);

    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName("server1");
    privilege.setDbName("default");
    privilege.setTableName("table1");
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());

    Set<String> users = Sets.newHashSet("user1");

    createRole(roleName);

    sentryStore.alterSentryRoleAddGroups(grantor, roleName, groups);
    sentryStore.alterSentryRoleDeleteGroups(roleName, groups);
    sentryStore.alterSentryRoleAddUsers(roleName, users);
    MSentryUser user = sentryStore.getMSentryUserByName(users.iterator().next());
    assertNotNull(user);

    sentryStore.alterSentryRoleDeleteUsers(roleName, users);
    user = sentryStore.getMSentryUserByName(users.iterator().next(), false);
    assertNull(user);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
  }

  @Test
  public void testURI() throws Exception {
    String roleName1 = "test-role1";
    String roleName2 = "test-role2";
    String grantor = "g1";
    String uri1 = "file:///var/folders/dt/9zm44z9s6bjfxbrm4v36lzdc0000gp/T/1401860678102-0/data/kv1.dat";
    String uri2 = "file:///var/folders/dt/9zm44z9s6bjfxbrm4v36lzdc0000gp/T/1401860678102-0/data/kv2.dat";
    createRole(roleName1);
    createRole(roleName2);
    TSentryPrivilege tSentryPrivilege1 = new TSentryPrivilege("URI", "server1", "ALL");
    tSentryPrivilege1.setURI(uri1);
    TSentryPrivilege tSentryPrivilege2 = new TSentryPrivilege("URI", "server1", "ALL");
    tSentryPrivilege2.setURI(uri2);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(tSentryPrivilege1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(tSentryPrivilege2), null);

    TSentryAuthorizable tSentryAuthorizable1 = new TSentryAuthorizable();
    tSentryAuthorizable1.setUri(uri1);
    tSentryAuthorizable1.setServer("server1");

    TSentryAuthorizable tSentryAuthorizable2 = new TSentryAuthorizable();
    tSentryAuthorizable2.setUri(uri2);
    tSentryAuthorizable2.setServer("server1");

    Set<TSentryPrivilege> privileges =
        sentryStore.getTSentryPrivileges(SentryPrincipalType.ROLE, new HashSet<String>(Arrays.asList(roleName1, roleName2)), tSentryAuthorizable1);

    assertTrue(privileges.size() == 1);

    //Test with other URI Authorizable
    privileges =
        sentryStore.getTSentryPrivileges(SentryPrincipalType.ROLE, new HashSet<String>(Arrays.asList(roleName1, roleName2)), tSentryAuthorizable2);
    assertTrue(privileges.size() == 1);

    Set<TSentryGroup> tSentryGroups = new HashSet<TSentryGroup>();
    tSentryGroups.add(new TSentryGroup("group1"));
    sentryStore.alterSentryRoleAddGroups(grantor, roleName1, tSentryGroups);
    sentryStore.alterSentryRoleAddUsers(roleName1, Sets.newHashSet("user1"));
    sentryStore.alterSentryRoleAddGroups(grantor, roleName2, tSentryGroups);
    sentryStore.alterSentryRoleAddUsers(roleName2, Sets.newHashSet("user1"));

    TSentryActiveRoleSet thriftRoleSet = new TSentryActiveRoleSet(true, new HashSet<String>(Arrays.asList(roleName1,roleName2)));

    // list privilege for group only
    Set<String> privs = sentryStore.listSentryPrivilegesForProvider(
        new HashSet<String>(Arrays.asList("group1")), Sets.newHashSet(""), thriftRoleSet,
        tSentryAuthorizable1);
    assertTrue(privs.size()==1);
    assertTrue(privs.contains("server=server1->uri=" + uri1 + "->action=all"));

    privs = sentryStore.listSentryPrivilegesForProvider(
        new HashSet<String>(Arrays.asList("group1")), Sets.newHashSet(""), thriftRoleSet,
        tSentryAuthorizable2);
    assertTrue(privs.size()==1);
    assertTrue(privs.contains("server=server1->uri=" + uri2 + "->action=all"));

    // list privilege for user only
    privs = sentryStore.listSentryPrivilegesForProvider(new HashSet<String>(Arrays.asList("")),
        Sets.newHashSet("user1"), thriftRoleSet, tSentryAuthorizable1);
    assertTrue(privs.size() == 1);
    assertTrue(privs.contains("server=server1->uri=" + uri1 + "->action=all"));

    privs = sentryStore.listSentryPrivilegesForProvider(new HashSet<String>(Arrays.asList("")),
        Sets.newHashSet("user1"), thriftRoleSet, tSentryAuthorizable2);
    assertTrue(privs.size() == 1);
    assertTrue(privs.contains("server=server1->uri=" + uri2 + "->action=all"));

    // list privilege for both user and group
    privs = sentryStore.listSentryPrivilegesForProvider(
        new HashSet<String>(Arrays.asList("group1")), Sets.newHashSet("user1"), thriftRoleSet,
        tSentryAuthorizable1);
    assertTrue(privs.size() == 1);
    assertTrue(privs.contains("server=server1->uri=" + uri1 + "->action=all"));

    privs = sentryStore.listSentryPrivilegesForProvider(
        new HashSet<String>(Arrays.asList("group1")), Sets.newHashSet("user1"), thriftRoleSet,
        tSentryAuthorizable2);
    assertTrue(privs.size() == 1);
    assertTrue(privs.contains("server=server1->uri=" + uri2 + "->action=all"));
  }

  @Test
  public void testURIGrantRevokeOnEmptyPath() throws Exception {
    String roleName = "test-empty-uri-role";
    String uri = "";
    createRole(roleName);
    TSentryPrivilege tSentryPrivilege = new TSentryPrivilege("URI", "server1", "ALL");
    tSentryPrivilege.setURI(uri);
    //Test grant on empty URI
    try {
      sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(tSentryPrivilege), null);
      fail("Expected SentryInvalidInputException");
    } catch(SentryInvalidInputException e) {
      // expected
    }
    //Test revoke on empty URI
    try {
      sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(tSentryPrivilege), null);
      fail("Expected SentryInvalidInputException");
    } catch(SentryInvalidInputException e) {
      // expected
    }
  }

  @Test
  public void testCreateDuplicateRole() throws Exception {
    String roleName = "test-dup-role";
    createRole(roleName);
    try {
      sentryStore.createSentryRole(roleName);
      fail("Expected SentryAlreadyExistsException");
    } catch(SentryAlreadyExistsException e) {
      // expected
    }
  }

  @Test
  public void testCaseSensitiveScope() throws Exception {
    String roleName = "role1";
    createRole(roleName);
    TSentryPrivilege sentryPrivilege = new TSentryPrivilege("Database", "server1", "all");
    sentryPrivilege.setDbName("db1");
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(sentryPrivilege), null);
  }

  /**
   * Create a new role and then destroy it
   * @throws Exception
   */
  @Test
  public void testCreateDropRole() throws Exception {
    String roleName = "test-drop-role";
    createRole(roleName);
    sentryStore.dropSentryRole(roleName);
    checkRoleDoesNotExist(roleName);
  }

  @Test
  public void testAddDeleteGroupsNonExistantRole()
      throws Exception {
    String roleName = "non-existant-role";
    String grantor = "g1";
    Set<TSentryGroup> groups = Sets.newHashSet();
    Set<String> users = Sets.newHashSet(grantor);
    try {
      sentryStore.alterSentryRoleAddGroups(grantor, roleName, groups);
      fail("Expected SentryNoSuchObjectException exception");
    } catch (SentryNoSuchObjectException e) {
      // excepted exception
    }
    try {
      sentryStore.alterSentryRoleAddUsers(roleName, users);
      fail("Expected SentryNoSuchObjectException exception");
    } catch (SentryNoSuchObjectException e) {
      // excepted exception
    }
  }

  @Test
  public void testAddDeleteGroups() throws Exception {
    String roleName = "test-groups";
    String grantor = "g1";
    createRole(roleName);
    Set<TSentryGroup> groups = Sets.newHashSet();
    TSentryGroup group = new TSentryGroup();
    group.setGroupName("test-groups-g1");
    groups.add(group);
    group = new TSentryGroup();
    group.setGroupName("test-groups-g2");
    groups.add(group);
    sentryStore.alterSentryRoleAddGroups(grantor, roleName, groups);
    sentryStore.alterSentryRoleDeleteGroups(roleName, groups);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    assertEquals(Collections.emptySet(), role.getGroups());
  }

  @Test
  public void testAddDeleteUsers() throws Exception {
    String roleName = "test-users";
    createRole(roleName);
    Set<String> users = Sets.newHashSet("test-user-u1", "test-user-u2");
    sentryStore.alterSentryRoleAddUsers(roleName, users);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    role.getUsers().size();
    sentryStore.alterSentryRoleDeleteUsers(roleName, users);
    role = sentryStore.getMSentryRoleByName(roleName);
    assertEquals(0, role.getUsers().size());
  }

  @Test
  public void testGetTSentryRolesForUser() throws Exception {
    // Test the method GetTSentryRolesForUser according to the following test data:
    // user1->group1
    // user2->group1
    // user3->group1, group2
    // user4->group2, group3
    // group1->r1
    // group2->r2
    // group3->r2
    // user2->r3
    // user4->r3
    String roleName1 = "r1";
    String roleName2 = "r2";
    String roleName3 = "r3";
    String user1 = "u1";
    String user2 = "u2";
    String user3 = "u3";
    String user4 = "u4";
    String group1 = "group1";
    String group2 = "group2";
    String group3 = "group3";
    Map<String, Set<String>> userToGroups = Maps.newHashMap();
    userToGroups.put(user1, Sets.newHashSet(group1));
    userToGroups.put(user2, Sets.newHashSet(group1));
    userToGroups.put(user3, Sets.newHashSet(group1, group2));
    userToGroups.put(user4, Sets.newHashSet(group2, group3));

    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);
    sentryStore.createSentryRole(roleName3);
    sentryStore.alterSentryRoleAddUsers(roleName1, Sets.newHashSet(user1));
    sentryStore.alterSentryRoleAddUsers(roleName2, Sets.newHashSet(user2));
    sentryStore.alterSentryRoleAddUsers(roleName2, Sets.newHashSet(user3));
    sentryStore.alterSentryRoleAddUsers(roleName3, Sets.newHashSet(user2, user4));

    Set<TSentryRole> roles = sentryStore.getTSentryRolesByUserNames(Sets.newHashSet(user1));
    assertEquals(1, roles.size());
    for (TSentryRole role : roles) {
      assertTrue(roleName1.equals(role.getRoleName()));
    }

    roles = sentryStore.getTSentryRolesByUserNames(Sets.newHashSet(user2));
    assertEquals(2, roles.size());
    for (TSentryRole role : roles) {
      assertTrue(roleName2.equals(role.getRoleName()) || roleName3.equals(role.getRoleName()));
    }

    roles = sentryStore.getTSentryRolesByUserNames(Sets.newHashSet(user3));
    assertEquals(1, roles.size());
    for (TSentryRole role : roles) {
      assertTrue(roleName2.equals(role.getRoleName()));
    }

    roles = sentryStore.getTSentryRolesByUserNames(Sets.newHashSet(user4));
    assertEquals(1, roles.size());
    for (TSentryRole role : roles) {
      assertTrue(roleName3.equals(role.getRoleName()));
    }
  }

  @Test
  public void testGetTSentryRolesForUsers() throws Exception {
    // Test the method getTSentryRolesByUserNames according to the following test data:
    // user1->r1
    // user2->r3
    // user3->r2
    // user4->r3, r2
    String roleName1 = "r1";
    String roleName2 = "r2";
    String roleName3 = "r3";
    String user1 = "u1";
    String user2 = "u2";
    String user3 = "u3";
    String user4 = "u4";

    createRole(roleName1);
    createRole(roleName2);
    createRole(roleName3);
    sentryStore.alterSentryRoleAddUsers(roleName1, Sets.newHashSet(user1));
    sentryStore.alterSentryRoleAddUsers(roleName2, Sets.newHashSet(user3));
    sentryStore.alterSentryRoleAddUsers(roleName2, Sets.newHashSet(user4));
    sentryStore.alterSentryRoleAddUsers(roleName3, Sets.newHashSet(user2, user4));

    Set<String> userSet1 = Sets.newHashSet(user1, user2, user3);
    Set<String> roleSet1 = Sets.newHashSet(roleName1, roleName2, roleName3);

    Set<String> userSet2 = Sets.newHashSet(user4);
    Set<String> roleSet2 = Sets.newHashSet(roleName2, roleName3);

    Set<String> userSet3 = Sets.newHashSet("foo");
    Set<String> roleSet3 = Sets.newHashSet();

    // Query for multiple users
    Set<String> roles = convertToRoleNameSet(sentryStore.getTSentryRolesByUserNames(userSet1));
    assertEquals("Returned roles should match the expected roles", 0, Sets.symmetricDifference(roles, roleSet1).size());

    // Query for single users
    roles = convertToRoleNameSet(sentryStore.getTSentryRolesByUserNames(userSet2));
    assertEquals("Returned roles should match the expected roles", 0, Sets.symmetricDifference(roles, roleSet2).size());

    // Query for non-existing user
    roles = convertToRoleNameSet(sentryStore.getTSentryRolesByUserNames(userSet3));
    assertEquals("Returned roles should match the expected roles", 0, Sets.symmetricDifference(roles, roleSet3).size());
  }

  private Set<String> convertToRoleNameSet(Set<TSentryRole> tSentryRoles) {
    Set<String> roleNameSet = Sets.newHashSet();
    for (TSentryRole role : tSentryRoles) {
      roleNameSet.add(role.getRoleName());
    }
    return roleNameSet;
  }

  @Test
  public void testGetTSentryRolesForGroups() throws Exception {
    // Test the method getRoleNamesForGroups according to the following test data:
    // group1->r1
    // group2->r2
    // group3->r2
    String grantor = "g1";
    String roleName1 = "r1";
    String roleName2 = "r2";
    String roleName3 = "r3";
    String group1 = "group1";
    String group2 = "group2";
    String group3 = "group3";

    createRole(roleName1);
    createRole(roleName2);
    createRole(roleName3);
    sentryStore.alterSentryRoleAddGroups(grantor, roleName1, Sets.newHashSet(new TSentryGroup(group1)));
    sentryStore.alterSentryRoleAddGroups(grantor, roleName2, Sets.newHashSet(new TSentryGroup(group2),
        new TSentryGroup(group3)));

    Set<String> groupSet1 = Sets.newHashSet(group1, group2, group3);
    Set<String> roleSet1 = Sets.newHashSet(roleName1, roleName2);

    Set<String> groupSet2 = Sets.newHashSet(group1);
    Set<String> roleSet2 = Sets.newHashSet(roleName1);

    Set<String> groupSet3 = Sets.newHashSet("foo");
    Set<String> roleSet3 = Sets.newHashSet();

    // Query for multiple groups
    Set<String> roles = sentryStore.getRoleNamesForGroups(groupSet1);
    assertEquals("Returned roles should match the expected roles", 0, Sets.symmetricDifference(roles, roleSet1).size());

    // Query for single group
    roles = sentryStore.getRoleNamesForGroups(groupSet2);
    assertEquals("Returned roles should match the expected roles", 0, Sets.symmetricDifference(roles, roleSet2).size());

    // Query for non-existing group
    roles = sentryStore.getRoleNamesForGroups(groupSet3);
    assertEquals("Returned roles should match the expected roles", 0, Sets.symmetricDifference(roles, roleSet3).size());
  }

  @Test
  public void testGrantRevokePrivilege() throws Exception {
    String roleName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    createRole(roleName);
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());
    privilege.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking SELECT, we should have INSERT
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());
    for (MSentryPrivilege mPrivilege : privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      assertEquals(table, mPrivilege.getTableName());
      assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
      assertFalse(mPrivilege.getGrantOption());
    }
    long numDBPrivs = sentryStore.countMSentryPrivileges();
    assertEquals("Privilege count", numDBPrivs,1);
  }

  private void verifyOrphanCleanup() throws Exception {
    assertFalse("Failed to cleanup orphaned privileges", sentryStore.findOrphanedPrivileges());
  }

  /**
   * Create several privileges in the database, then delete the role that
   * created them.  This makes them all orphans.  Wait a bit to ensure the
   * cleanup thread runs, and expect them all to be gone from the database.
   * @throws Exception
   */
 // @Ignore("Disabled with SENTRY-545 following SENTRY-140 problems")
  @Test
  public void testPrivilegeCleanup() throws Exception {
    final String roleName = "test-priv-cleanup";
    final String server = "server";
    final String dBase = "db";
    final String table = "table-";

    createRole(roleName);

    // Create NUM_PRIVS unique privilege objects in the database
    for (int i = 0; i < NUM_PRIVS; i++) {
      TSentryPrivilege priv = new TSentryPrivilege();
      priv.setPrivilegeScope("TABLE");
      priv.setServerName(server);
      priv.setAction(AccessConstants.ALL);
      priv.setCreateTime(System.currentTimeMillis());
      priv.setTableName(table + i);
      priv.setDbName(dBase);
      sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);
    }

    // Make sure we really have the expected number of privs in the database
     assertEquals(sentryStore.countMSentryPrivileges(), NUM_PRIVS);

    // Now to make a bunch of orphans, we just remove the role that
    // created them.
    sentryStore.dropSentryRole(roleName);

    // Now wait and see if the orphans get cleaned up
    verifyOrphanCleanup();

    List<MSentryPrivilege> list = sentryStore.getAllMSentryPrivileges();
    assertEquals(list.size(), 0);
  }

  /**
   * Much like testPrivilegeCleanup, make a lot of privileges and make sure
   * they get cleaned up.  The difference here is that the privileges are
   * created by granting ALL and then removing SELECT - thus leaving INSERT.
   * This test exists because the revocation plays havoc with the orphan
   * cleanup thread.
   * @throws Exception
   */
 // @Ignore("Disabled with SENTRY-545 following SENTRY-140 problems")
  @Test
  public void testPrivilegeCleanup2() throws Exception {
    final String roleName = "test-priv-cleanup";
    final String server = "server";
    final String dBase = "db";
    final String table = "table-";

    createRole(roleName);

    // Create NUM_PRIVS unique privilege objects in the database once more,
    // this time granting ALL and revoking SELECT to make INSERT.
    for (int i=0 ; i < NUM_PRIVS; i++) {
      TSentryPrivilege priv = new TSentryPrivilege();
      priv.setPrivilegeScope("DATABASE");
      priv.setServerName(server);
      priv.setAction(AccessConstants.ALL);
      priv.setCreateTime(System.currentTimeMillis());
      priv.setTableName(table + i);
      priv.setDbName(dBase);
      priv.setGrantOption(TSentryGrantOption.TRUE);
      sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      priv.setAction(AccessConstants.SELECT);
      priv.setGrantOption(TSentryGrantOption.UNSET);
      sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);
      // after having ALL and revoking SELECT, we should have INSERT
      MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
      Set<MSentryPrivilege> privileges = role.getPrivileges();
      assertEquals(privileges.toString(), 1 * (i+1), privileges.size());
      for ( MSentryPrivilege mSentryPrivilege : privileges) {
        assertNotSame(AccessConstants.INSERT, mSentryPrivilege.getAction());
        assertNotSame(AccessConstants.ALL, mSentryPrivilege.getAction());
      }
    }

    // Drop the role and clean up as before
    sentryStore.dropSentryRole(roleName);
    verifyOrphanCleanup();
    //There should not be any Privileges left
    List<MSentryPrivilege> list = sentryStore.getAllMSentryPrivileges();
    assertEquals(list.size(), 0);
  }

  /**
   * This method tries to add ALL privileges on
   * databases to a role and immediately revokes
   * SELECT and INSERT privileges. At the end of
   * each iteration we should not find any privileges
   * for that role. Finally we should not find any
   * privileges, as we are cleaning up orphan privileges
   * immediately.
   * @throws Exception
   */
  @Test
  public void testPrivilegeCleanup3() throws Exception {
    final String roleName = "test-priv-cleanup";
    final String server = "server";
    final String dBase = "db";
    final String table = "table-";

    createRole(roleName);

    // Create NUM_PRIVS unique privilege objects in the database once more,
    // this time granting ALL and revoking SELECT to make INSERT.
    for (int i=0 ; i < NUM_PRIVS; i++) {
      TSentryPrivilege priv = new TSentryPrivilege();
      priv.setPrivilegeScope("DATABASE");
      priv.setServerName(server);
      priv.setAction(AccessConstants.ALL);
      priv.setCreateTime(System.currentTimeMillis());
      priv.setTableName(table + i);
      priv.setDbName(dBase);
      priv.setGrantOption(TSentryGrantOption.TRUE);
      sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      priv.setAction(AccessConstants.SELECT);
      priv.setGrantOption(TSentryGrantOption.UNSET);
      sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      assertFalse(sentryStore.findOrphanedPrivileges());

      //After having ALL and revoking SELECT, we should have INSERT
      //Remove the INSERT privilege as well.
      //There should not be any more privileges in the sentry store
      priv.setAction(AccessConstants.INSERT);
      sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
      assertEquals("Privilege Count", 0, role.getPrivileges().size());

      priv.setAction(AccessConstants.CREATE);
      sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      role = sentryStore.getMSentryRoleByName(roleName);
      assertEquals("Privilege Count", 0, role.getPrivileges().size());

      priv.setAction(AccessConstants.DROP);
      sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      role = sentryStore.getMSentryRoleByName(roleName);
      assertEquals("Privilege Count", 0, role.getPrivileges().size());

      priv.setAction(AccessConstants.ALTER);
      sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      role = sentryStore.getMSentryRoleByName(roleName);
      assertEquals("Privilege Count", 0, role.getPrivileges().size());
    }

    // Drop the role and clean up as before
    verifyOrphanCleanup();

    //There should not be any Privileges left
    List<MSentryPrivilege> list = sentryStore.getAllMSentryPrivileges();
    assertEquals(list.size(), 0);

  }

  /**
   * This method "n" privileges with action "ALL" on
   * tables to a role. Later we are revoking insert
   * and select privileges to of the tables making the
   * the privilege orphan. Finally we should find only
   * n -1 privileges, as we are cleaning up orphan
   * privileges immediately.
   * @throws Exception
   */
  @Test
  public void testPrivilegeCleanup4 () throws Exception {
    final String roleName = "test-priv-cleanup";
    final String server = "server";
    final String dBase = "db";
    final String table = "table-";

    createRole(roleName);

    // Create NUM_PRIVS unique privilege objects in the database
    for (int i = 0; i < NUM_PRIVS; i++) {
      TSentryPrivilege priv = new TSentryPrivilege();
      priv.setPrivilegeScope("TABLE");
      priv.setServerName(server);
      priv.setAction(AccessConstants.ALL);
      priv.setCreateTime(System.currentTimeMillis());
      priv.setTableName(table + i);
      priv.setDbName(dBase);
      sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);
    }

    // Make sure we really have the expected number of privs in the database
    assertEquals(sentryStore.countMSentryPrivileges(), NUM_PRIVS);

    //Revoking INSERT privilege. This is change the privilege to SELECT, CREATE, DROP, ALTER
    TSentryPrivilege priv = new TSentryPrivilege();
    priv.setPrivilegeScope("TABLE");
    priv.setServerName(server);
    priv.setAction(AccessConstants.INSERT);
    priv.setCreateTime(System.currentTimeMillis());
    priv.setTableName(table + '0');
    priv.setDbName(dBase);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

    //There should be SELECT privilege in the sentry store
    priv = new TSentryPrivilege();
    priv.setPrivilegeScope("TABLE");
    priv.setServerName(server);
    priv.setAction(AccessConstants.SELECT);
    priv.setCreateTime(System.currentTimeMillis());
    priv.setTableName(table + '0');
    priv.setDbName(dBase);
    MSentryPrivilege mPriv = sentryStore.findMSentryPrivilegeFromTSentryPrivilege(priv);
    assertNotNull(mPriv);

    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);

    // should have NUM_PRIVS - 1 ALL privileges, and 4 privileges (SELECT, CREATE, DROP, ALTER)
    assertEquals("Privilege Count", NUM_PRIVS, role.getPrivileges().size());

    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);
    role = sentryStore.getMSentryRoleByName(roleName);
    assertEquals("Privilege Count", NUM_PRIVS - 1, role.getPrivileges().size());

  }

  /**
   * This method tries to add alter privileges on
   * databases to a role and immediately revokes
   * them. At the end of each iteration we should
   * not find any privileges for that role
   * Finally we should not find any privileges, as
   * we are cleaning up orphan privileges immediately.
   * @throws Exception
   */
  @Test
  public void testPrivilegeCleanup5() throws Exception {
    final String roleName = "test-priv-cleanup";
    final String server = "server";
    final String dBase = "db";
    final String table = "table-";

    createRole(roleName);

    // Create NUM_PRIVS unique privilege objects in the database once more,
    // this time granting ALL and revoking SELECT to make INSERT.
    for (int i=0 ; i < NUM_PRIVS; i++) {
      TSentryPrivilege priv = new TSentryPrivilege();
      priv.setPrivilegeScope("DATABASE");
      priv.setServerName(server);
      priv.setAction(AccessConstants.ALTER);
      priv.setCreateTime(System.currentTimeMillis());
      priv.setTableName(table + i);
      priv.setDbName(dBase);
      priv.setGrantOption(TSentryGrantOption.TRUE);
      sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      priv.setAction(AccessConstants.ALTER);
      sentryStore.alterSentryRevokePrivileges( SentryPrincipalType.ROLE, roleName, Sets.newHashSet(priv), null);

      MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
      assertEquals("Privilege Count", 0, role.getPrivileges().size());
    }
    //There should not be any Privileges left
    List<MSentryPrivilege> list = sentryStore.getAllMSentryPrivileges();
    assertEquals(list.size(), 0);

  }

  @Test
  public void testDropIndividualPrivilegesWhenGrantAllIsGranted() throws Exception {
    final String ROLE_NAME = "r1";
    final String SERVER_NAME = "server1";
    final String DB_NAME = "db1";
    final String TABLE_NAME = "table1";

    TSentryPrivilege allPrivilege = toTSentryPrivilege(AccessConstants.ACTION_ALL,
      PrivilegeScope.SERVER.toString(), SERVER_NAME, DB_NAME, TABLE_NAME, TSentryGrantOption.FALSE);

    TSentryPrivilege allWithGrant = toTSentryPrivilege(AccessConstants.ACTION_ALL,
      PrivilegeScope.SERVER.toString(), SERVER_NAME, DB_NAME, TABLE_NAME, TSentryGrantOption.TRUE);

    TSentryPrivilege ownerPrivilege = toTSentryPrivilege(AccessConstants.OWNER,
      PrivilegeScope.DATABASE.toString(), SERVER_NAME, DB_NAME, TABLE_NAME);

    Set<TSentryPrivilege> grantPrivileges = Sets.newHashSet(
      toTSentryPrivilege(AccessConstants.SELECT, PrivilegeScope.SERVER.toString(), SERVER_NAME,
        DB_NAME, TABLE_NAME),
      toTSentryPrivilege(AccessConstants.INSERT, PrivilegeScope.SERVER.toString(), SERVER_NAME,
        DB_NAME, TABLE_NAME),
      toTSentryPrivilege(AccessConstants.CREATE, PrivilegeScope.SERVER.toString(), SERVER_NAME,
        DB_NAME, TABLE_NAME),
      toTSentryPrivilege(AccessConstants.ALTER, PrivilegeScope.SERVER.toString(), SERVER_NAME,
        DB_NAME, TABLE_NAME),
      toTSentryPrivilege(AccessConstants.DROP, PrivilegeScope.SERVER.toString(), SERVER_NAME,
        DB_NAME, TABLE_NAME),
      toTSentryPrivilege(AccessConstants.INDEX, PrivilegeScope.SERVER.toString(), SERVER_NAME,
        DB_NAME, TABLE_NAME),
      toTSentryPrivilege(AccessConstants.LOCK, PrivilegeScope.SERVER.toString(), SERVER_NAME,
        DB_NAME, TABLE_NAME),

      // This special privilege will not be removed when granting all privileges
      ownerPrivilege
    );

    // Grant individual privileges to a role
    createRole(ROLE_NAME);
    sentryStore.alterSentryRoleGrantPrivileges(ROLE_NAME, grantPrivileges);

    // Check those individual privileges are granted
    Set<TSentryPrivilege> rolePrivileges = sentryStore.getAllTSentryPrivilegesByRoleName(ROLE_NAME);
    assertEquals(grantPrivileges.size(), rolePrivileges.size());
    for (TSentryPrivilege privilege : grantPrivileges) {
      assertTrue(String.format("Privilege %s was not granted.", privilege.getAction()),
        rolePrivileges.contains(privilege));
    }

    // Grant the ALL privilege (this should remove all individual privileges, and grant only ALL)
    sentryStore.alterSentryRoleGrantPrivileges(ROLE_NAME, Sets.newHashSet(allPrivilege));

    // Check the ALL and OWNER privileges are the only privileges
    rolePrivileges = sentryStore.getAllTSentryPrivilegesByRoleName(ROLE_NAME);
    assertEquals(2, rolePrivileges.size()); // ALL and OWNER privileges should be there
    assertTrue("Privilege ALL was not granted.", rolePrivileges.contains(allPrivilege));
    assertTrue("Privilege OWNER was dropped.", rolePrivileges.contains(ownerPrivilege));

    // Check the ALL WITH GRANT privilege just replaces the ALL and keeps the OWNER privilege
    sentryStore.alterSentryRoleGrantPrivileges(ROLE_NAME, Sets.newHashSet(allWithGrant));
    rolePrivileges = sentryStore.getAllTSentryPrivilegesByRoleName(ROLE_NAME);
    assertTrue("Privilege ALL WITH GRANT was not granted.", rolePrivileges.contains(allWithGrant));
    assertTrue("Privilege OWNER was dropped.", rolePrivileges.contains(ownerPrivilege));

    // Check the ALL privilege just replaces the ALL WITH GRANT and keeps the OWNER privilege
    sentryStore.alterSentryRoleGrantPrivileges(ROLE_NAME, Sets.newHashSet(allPrivilege));
    rolePrivileges = sentryStore.getAllTSentryPrivilegesByRoleName(ROLE_NAME);
    assertTrue("Privilege ALL was not granted.", rolePrivileges.contains(allPrivilege));
    assertTrue("Privilege OWNER was dropped.", rolePrivileges.contains(ownerPrivilege));


    // Clean-up test
    sentryStore.dropSentryRole(ROLE_NAME);
  }

  //TODO Use new transaction Manager logic, Instead of

  @Test
  public void testGrantRevokeMultiPrivileges() throws Exception {
    String roleName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    String[] columns = {"c1","c2","c3","c4"};
    createRole(roleName);
    Set<TSentryPrivilege> tPrivileges = Sets.newHashSet();
    for (String column : columns) {
      TSentryPrivilege privilege = new TSentryPrivilege();
      privilege.setPrivilegeScope("Column");
      privilege.setServerName(server);
      privilege.setDbName(db);
      privilege.setTableName(table);
      privilege.setColumnName(column);
      privilege.setAction(AccessConstants.SELECT);
      privilege.setCreateTime(System.currentTimeMillis());
      tPrivileges.add(privilege);
    }
    sentryStore.alterSentryRoleGrantPrivileges(roleName, tPrivileges);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 4, privileges.size());

    tPrivileges = Sets.newHashSet();
    for (int i = 0; i < 2; i++) {
      TSentryPrivilege privilege = new TSentryPrivilege();
      privilege.setPrivilegeScope("Column");
      privilege.setServerName(server);
      privilege.setDbName(db);
      privilege.setTableName(table);
      privilege.setColumnName(columns[i]);
      privilege.setAction(AccessConstants.SELECT);
      privilege.setCreateTime(System.currentTimeMillis());
      tPrivileges.add(privilege);
    }
    sentryStore.alterSentryRoleRevokePrivileges(roleName, tPrivileges);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());

    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("Table");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.SELECT);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    // After revoking table scope, we will have 0 privileges
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 0, privileges.size());
  }

  /**
   * Regression test for SENTRY-74 and SENTRY-552
   */
  @Test
  public void testGrantRevokePrivilegeWithColumn() throws Exception {
    String roleName = "test-col-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    String column1 = "c1";
    String column2 = "c2";
    createRole(roleName);
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("COLUMN");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setColumnName(column1);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());

    // Grant ALL on c1 and c2
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    privilege.setColumnName(column2);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());

    // Revoke SELECT on c2
    privilege.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);

    // At this point c1 has ALL privileges and c2 should have (INSERT, CREATE, DROP, ALTER)
    // after revoking SELECT
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());
    for (MSentryPrivilege mPrivilege: privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      assertEquals(table, mPrivilege.getTableName());
      assertFalse(mPrivilege.getGrantOption());
      if (mPrivilege.getColumnName().equals(column1)) {
        assertEquals(AccessConstants.ALL, mPrivilege.getAction());
      } else if (mPrivilege.getColumnName().equals(column2)) {
        assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
        assertNotSame(AccessConstants.ALL, mPrivilege.getAction());
      } else {
        fail("Unexpected column name: " + mPrivilege.getColumnName());
      }
    }

    // after revoking INSERT table level privilege will remove INSERT privileges from column2
    // and downgrade column1 to (SELECT) privileges.
    privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.INSERT);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    // Revoke ALL from the table should now remove all the column privileges.
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 0, privileges.size());
  }

  /**
   * Regression test for SENTRY-552
   */
  @Test
  public void testGrantRevokeTablePrivilegeDowngradeByDb() throws Exception {
    String roleName = "test-table-db-downgrade-privilege";
    String server = "server1";
    String db = "db1";
    String table1 = "tbl1";
    String table2 = "tbl2";
    createRole(roleName);
    TSentryPrivilege privilegeTable1 = new TSentryPrivilege();
    privilegeTable1.setPrivilegeScope("TABLE");
    privilegeTable1.setServerName(server);
    privilegeTable1.setDbName(db);
    privilegeTable1.setTableName(table1);
    privilegeTable1.setAction(AccessConstants.ALL);
    privilegeTable1.setCreateTime(System.currentTimeMillis());
    TSentryPrivilege privilegeTable2 = privilegeTable1.deepCopy();
    privilegeTable2.setTableName(table2);

    // Grant ALL on table1 and table2
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeTable1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeTable2), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());

    // Revoke SELECT on table2
    privilegeTable2.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeTable2), null);
    // after having ALL and revoking SELECT, we should have (INSERT) at table2
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());

    for (MSentryPrivilege mPrivilege: privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      assertFalse(mPrivilege.getGrantOption());
      if (mPrivilege.getTableName().equals(table1)) {
        assertEquals(AccessConstants.ALL, mPrivilege.getAction());
      } else if (mPrivilege.getTableName().equals(table2)) {
        assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
        assertNotSame(AccessConstants.ALL, mPrivilege.getAction());
      } else {
        fail("Unexpected table name: " + mPrivilege.getTableName());
      }
    }

    // Revoke INSERT on Database
    privilegeTable2.setAction(AccessConstants.INSERT);
    privilegeTable2.setPrivilegeScope("DATABASE");
    privilegeTable2.unsetTableName();
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeTable2), null);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();

    // after revoking INSERT database level privilege
    // table1 should have (SELECT)
    // table2 should have ()
    assertEquals(privileges.toString(), 1, privileges.size());
    for (MSentryPrivilege mPrivilege : privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      if (table1.equals(mPrivilege.getTableName())) {
        assertNotSame(AccessConstants.INSERT, mPrivilege.getAction());
        assertNotSame(AccessConstants.ALL, mPrivilege.getAction());
      } else if (table2.equals(mPrivilege.getTableName())) {
        assertNotSame(AccessConstants.INSERT, mPrivilege.getAction());
        assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
        assertNotSame(AccessConstants.ALL, mPrivilege.getAction());
      }
      assertFalse(mPrivilege.getGrantOption());
    }
  }

  /**
   * Regression test for SENTRY-552
   */
  @Test
  public void testGrantRevokeColumnPrivilegeDowngradeByDb() throws Exception {
    String roleName = "test-column-db-downgrade-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    String column1 = "c1";
    String column2 = "c2";
    createRole(roleName);
    TSentryPrivilege privilegeCol1 = new TSentryPrivilege();
    privilegeCol1.setPrivilegeScope("COLUMN");
    privilegeCol1.setServerName(server);
    privilegeCol1.setDbName(db);
    privilegeCol1.setTableName(table);
    privilegeCol1.setColumnName(column1);
    privilegeCol1.setAction(AccessConstants.ALL);
    privilegeCol1.setCreateTime(System.currentTimeMillis());
    TSentryPrivilege privilegeCol2 = privilegeCol1.deepCopy();
    privilegeCol2.setColumnName(column2);

    // Grant ALL on column1 and column2
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeCol1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeCol2), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());

    // Revoke SELECT on column2
    privilegeCol2.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeCol2), null);
    // after having ALL and revoking SELECT, we should have (INSERT)
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());

    for (MSentryPrivilege mPrivilege: privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      assertEquals(table, mPrivilege.getTableName());
      assertFalse(mPrivilege.getGrantOption());
      if (mPrivilege.getColumnName().equals(column1)) {
        assertEquals(AccessConstants.ALL, mPrivilege.getAction());
      } else if (mPrivilege.getColumnName().equals(column2)) {
        assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
      } else {
        fail("Unexpected column name: " + mPrivilege.getColumnName());
      }
    }

    // Revoke INSERT on Database
    privilegeCol2.setAction(AccessConstants.INSERT);
    privilegeCol2.setPrivilegeScope("DATABASE");
    privilegeCol2.unsetTableName();
    privilegeCol2.unsetColumnName();
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilegeCol2), null);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();

    // after revoking INSERT database level privilege
    // column2 has ()
    // and downgrade column1 to (SELECT) privileges.
    assertEquals(privileges.toString(), 1, privileges.size());
    for (MSentryPrivilege mPrivilege : privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      assertEquals(table, mPrivilege.getTableName());
      if (column1.equals(mPrivilege.getColumnName())) {
        assertNotSame(AccessConstants.INSERT, mPrivilege.getAction());
      } else if (column1.equals(mPrivilege.getColumnName())) {
        assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
        assertNotSame(AccessConstants.INSERT, mPrivilege.getAction());
      }
      assertFalse(mPrivilege.getGrantOption());
    }
  }

  @Test
  public void testGrantRevokePrivilegeWithGrantOption() throws Exception {
    String roleName = "test-grantOption-table";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    TSentryGrantOption grantOption = TSentryGrantOption.TRUE;
    createRole(roleName);

    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    privilege.setGrantOption(grantOption);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());
    assertEquals(Boolean.valueOf(privilege.getGrantOption().toString()), Iterables.get(privileges, 0).getGrantOption());
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(0, privileges.size());

    roleName = "test-grantOption-db";

    createRole(roleName);
    privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("DATABASE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setAction(AccessConstants.ALL);
    privilege.setGrantOption(TSentryGrantOption.TRUE);
    privilege.setCreateTime(System.currentTimeMillis());
    privilege.setGrantOption(grantOption);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    privilege.setAction(AccessConstants.SELECT);
    privilege.setGrantOption(TSentryGrantOption.UNSET);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking SELECT, we should have (INSERT)
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());
    for (MSentryPrivilege mPrivilege : privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
    }
  }

  @Test
  public void testRevokeAllGrantOption() throws Exception {
    // 1. set local group mapping
    // user0->group0->role0
    String grantor = "g1";
    String[] users = {"user0"};
    String[] roles = {"role0"};
    String[] groups = {"group0"};
    for (int i = 0; i < users.length; i++) {
      addGroupsToUser(users[i], groups[i]);
      sentryStore.createSentryRole(roles[i]);
      Set<TSentryGroup> tGroups = Sets.newHashSet();
      TSentryGroup tGroup = new TSentryGroup(groups[i]);
      tGroups.add(tGroup);
      sentryStore.alterSentryRoleAddGroups(grantor, roles[i], tGroups);
    }
    writePolicyFile();

    // 2. g1 grant select on table tb1 to role0, with grant option
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    String roleName = roles[0];
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.SELECT);
    privilege.setCreateTime(System.currentTimeMillis());
    privilege.setGrantOption(TSentryGrantOption.TRUE);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);

    // 3. g1 grant select on table tb1 to role0, no grant option
    roleName = roles[0];
    privilege.setGrantOption(TSentryGrantOption.FALSE);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);

    // 4. g1 revoke all privilege from role0
    roleName = roles[0];
    privilege.setGrantOption(TSentryGrantOption.UNSET);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 0, privileges.size());
  }

  @Test
  public void testGrantDuplicatePrivilege() throws Exception {
    String roleName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    createRole(roleName);
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    privilege.setServerName("Server1");
    privilege.setDbName("DB1");
    privilege.setTableName("TBL1");
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());
  }

  @Test
  public void testListSentryPrivilegesForProvider() throws Exception {
    String roleName1 = "list-privs-r1", roleName2 = "list-privs-r2";
    String groupName1 = "list-privs-g1", groupName2 = "list-privs-g2";
    String userName1 = "list-privs-u1", userName2 = "list-privs-u2";
    String userWithoutRole = "user-no-privs";
    Set<String> noRoleUsers = Sets.newHashSet(userWithoutRole);
    String grantor = "g1";
    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);
    TSentryPrivilege privilege1 = new TSentryPrivilege();
    privilege1.setPrivilegeScope("TABLE");
    privilege1.setServerName("server1");
    privilege1.setDbName("db1");
    privilege1.setTableName("tbl1");
    privilege1.setAction("SELECT");
    privilege1.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege1), null);
    TSentryPrivilege privilege2 = new TSentryPrivilege();
    privilege2.setPrivilegeScope("SERVER");
    privilege2.setServerName("server1");
    privilege2.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege2), null);
    Set<TSentryGroup> groups = Sets.newHashSet();
    Set<String> users = Sets.newHashSet();
    TSentryGroup group = new TSentryGroup();
    group.setGroupName(groupName1);
    groups.add(group);
    users.add(userName1);
    sentryStore.alterSentryRoleAddGroups(grantor, roleName1, groups);
    sentryStore.alterSentryRoleAddUsers(roleName1, users);
    groups.clear();
    users.clear();
    group = new TSentryGroup();
    group.setGroupName(groupName2);
    groups.add(group);
    users.add(userName2);
    // group 2 and user2 has both roles 1 and 2
    sentryStore.alterSentryRoleAddGroups(grantor, roleName1, groups);
    sentryStore.alterSentryRoleAddGroups(grantor, roleName2, groups);
    sentryStore.alterSentryRoleAddUsers(roleName1, users);
    sentryStore.alterSentryRoleAddUsers(roleName2, users);
    // group1 all roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(Sets
            .newHashSet(groupName1), noRoleUsers, new TSentryActiveRoleSet(true,
            new HashSet<String>()))));
    // user1 all roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(Sets
            .newHashSet(""), Sets.newHashSet(userName1), new TSentryActiveRoleSet(true,
            new HashSet<String>()))));
    // group1 and user1 all roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(Sets
            .newHashSet(groupName1), Sets.newHashSet(userName1), new TSentryActiveRoleSet(true,
            new HashSet<String>()))));
    // one active role
    assertEquals(
        Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(
            Sets.newHashSet(groupName1), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet(roleName1)))));
    // unknown active role
    assertEquals(
        Sets.newHashSet(),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(
            Sets.newHashSet(groupName1), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet("not a role")))));
    // no active roles
    assertEquals(Sets.newHashSet(), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName1), noRoleUsers,
            new TSentryActiveRoleSet(false, new HashSet<String>()))));

    // group2 all roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select",
        "server=server1"), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName2), Sets.newHashSet(""),
            new TSentryActiveRoleSet(true, new HashSet<String>()))));
    // user2 all roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select",
        "server=server1"), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(""), Sets.newHashSet(userName2),
            new TSentryActiveRoleSet(true, new HashSet<String>()))));
    // user2 and group2 all roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select",
        "server=server1"), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName2),
            Sets.newHashSet(userName2), new TSentryActiveRoleSet(true, new HashSet<String>()))));

    // one active role
    assertEquals(
        Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(
            Sets.newHashSet(groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet(roleName1)))));
    assertEquals(
        Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select", "server=server1"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(
            Sets.newHashSet(groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet(roleName2)))));
    // unknown active role
    assertEquals(
        Sets.newHashSet(),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(
            Sets.newHashSet(groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet("not a role")))));
    // no active roles
    assertEquals(Sets.newHashSet(), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, new HashSet<String>()))));

    // both groups, all active roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select",
        "server=server1"), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName1, groupName2), noRoleUsers,
            new TSentryActiveRoleSet(true, new HashSet<String>()))));
    // both users and groups, all active roles
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select",
        "server=server1"), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName1, groupName2), Sets
            .newHashSet(userName1, userName2),
            new TSentryActiveRoleSet(true, new HashSet<String>()))));
    // one active role
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(Sets.newHashSet(
            groupName1, groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet(roleName1)))));
    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select",
        "server=server1"), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName1, groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet(roleName2)))));
    // unknown active role
    assertEquals(Sets.newHashSet(), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName1, groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, Sets.newHashSet("not a role")))));
    // no active roles
    assertEquals(Sets.newHashSet(), SentryStore.toTrimedLower(sentryStore
        .listAllSentryPrivilegesForProvider(Sets.newHashSet(groupName1, groupName2), noRoleUsers,
            new TSentryActiveRoleSet(false, new HashSet<String>()))));
  }

  @Test
  public void testListRole() throws Exception {
    String roleName1 = "role1", roleName2 = "role2", roleName3 = "role3";
    String group1 = "group1", group2 = "group2";
    String grantor = "g1";

    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);
    sentryStore.createSentryRole(roleName3);

    sentryStore.alterSentryRoleAddGroups(grantor, roleName1, Sets.newHashSet(new TSentryGroup(group1)));
    sentryStore.alterSentryRoleAddGroups(grantor, roleName2, Sets.newHashSet(new TSentryGroup(group2)));
    sentryStore.alterSentryRoleAddGroups(grantor, roleName3,
        Sets.newHashSet(new TSentryGroup(group1), new TSentryGroup(group2)));

    assertEquals(2, sentryStore.getTSentryRolesByGroupName(Sets.newHashSet(group1), false).size());
    assertEquals(2, sentryStore.getTSentryRolesByGroupName(Sets.newHashSet(group2), false).size());
    assertEquals(3, sentryStore.getTSentryRolesByGroupName(Sets.newHashSet(group1,group2), false).size());
    assertEquals(0,
        sentryStore.getTSentryRolesByGroupName(Sets.newHashSet("foo"), true)
            .size());
  }

  /**
   * Assign multiple table and SERVER privileges to roles and users
   * drop privilege for the object verify that it's removed correctly
   * @throws Exception
   */
  @Test
  public void testDropDbObject() throws Exception {
    String roleName1 = "list-privs-r1", roleName2 = "list-privs-r2", roleName3 = "list-privs-r3";
    String userName1 = "user-1", userName2 = "user-2";
    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);
    sentryStore.createSentryRole(roleName3);
    sentryStore.createSentryUser(userName1);
    sentryStore.createSentryUser(userName2);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege1 = new TSentryPrivilege(privilege_tbl1);
    privilege1.setAction("SELECT");

    TSentryPrivilege privilege2_1 = new TSentryPrivilege(privilege_tbl1);
    privilege2_1.setAction("INSERT");
    TSentryPrivilege privilege3_1 = new TSentryPrivilege(privilege_tbl1);
    privilege3_1.setAction("*");

    TSentryPrivilege privilege_server = new TSentryPrivilege();
    privilege_server.setPrivilegeScope("SERVER");
    privilege_server.setServerName("server1");
    privilege_server.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl2 = new TSentryPrivilege();
    privilege_tbl2.setPrivilegeScope("TABLE");
    privilege_tbl2.setServerName("server1");
    privilege_tbl2.setDbName("db1");
    privilege_tbl2.setTableName("tbl2");
    privilege_tbl2.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege2_3 = new TSentryPrivilege(privilege_tbl2);
    privilege2_3.setAction("SELECT");

    TSentryPrivilege privilege3_2 = new TSentryPrivilege(privilege_tbl2);
    privilege3_2.setAction("INSERT");

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege1), null);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege2_1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege_server), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege2_3), null);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName3, Sets.newHashSet(privilege3_1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName3, Sets.newHashSet(privilege3_2), null);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName1, Sets.newHashSet(privilege1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName2, Sets.newHashSet(privilege2_3), null);


    sentryStore.dropPrivilege(toTSentryAuthorizable(privilege_tbl1));
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1)
        .size());
    assertEquals(2, sentryStore.getAllTSentryPrivilegesByRoleName(roleName2)
        .size());
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByRoleName(roleName3)
        .size());


    try {
      sentryStore.getAllTSentryPrivilegesByUserName(userName1);
      fail("Should have received an exception");
    } catch (Exception e) {

    }
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByUserName(userName2)
            .size());
    sentryStore.dropPrivilege(toTSentryAuthorizable(privilege_tbl2));
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1)
        .size());
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByRoleName(roleName2)
        .size());
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName3)
        .size());
    try {
      sentryStore.getAllTSentryPrivilegesByUserName(userName2);
      fail("Should have received an exception");
    } catch (Exception e) {
    }
  }

  /**
   * Grants owner privileges to role/user and updates the owner
   * and makes sure that the owner privilege is updated.
   * @throws Exception
   */
  @Test
  public void testUpdateOwnerPrivilege() throws Exception {
    String roleName1 = "list-privs-r1", roleName2 = "list-privs-r2", roleName3 = "list-privs-r3";
    String userName1 = "user1", userName2 = "user2";
    List<SentryOwnerInfo> ownerInfoList  = null;
    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);
    sentryStore.createSentryRole(roleName3);
    sentryStore.createSentryUser(userName1);
    sentryStore.createSentryUser(userName2);


    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction("OWNER");

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer("server1");
    tSentryAuthorizable.setDb("db1");
    tSentryAuthorizable.setTable("tbl1");

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1), null);

    assertEquals(1, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1)
            .size());
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName2)
            .size());

    ownerInfoList  = sentryStore.listOwnersByAuthorizable(tSentryAuthorizable);
    assertEquals(1, ownerInfoList.size());
    assertEquals(SentryPrincipalType.ROLE, ownerInfoList.get(0).getOwnerType());
    assertEquals(roleName1, ownerInfoList.get(0).getOwnerName());


    // Change owner from a one role to another role
    sentryStore.updateOwnerPrivilege(tSentryAuthorizable, roleName2, SentryPrincipalType.ROLE, null);
    ownerInfoList  = sentryStore.listOwnersByAuthorizable(tSentryAuthorizable);
    assertEquals(1, ownerInfoList.size());
    assertEquals(SentryPrincipalType.ROLE, ownerInfoList.get(0).getOwnerType());
    assertEquals(roleName2, ownerInfoList.get(0).getOwnerName());

    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1)
            .size());
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByRoleName(roleName2)
            .size());

    tSentryAuthorizable.setTable("tbl2");
    TSentryPrivilege privilege_tbl2 = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl2.setTableName("tbl2");

    // Change owner from a one user to another user
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER,userName1, Sets.newHashSet(privilege_tbl2), null);
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByUserName(userName1)
            .size());



    sentryStore.updateOwnerPrivilege(tSentryAuthorizable, userName2, SentryPrincipalType.USER, null);
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByUserName(userName2)
            .size());
    ownerInfoList  = sentryStore.listOwnersByAuthorizable(tSentryAuthorizable);
    assertEquals(1, ownerInfoList.size());
    assertEquals(SentryPrincipalType.USER, ownerInfoList.get(0).getOwnerType());
    assertEquals(userName2, ownerInfoList.get(0).getOwnerName());

  // Change owner from a user to role
    sentryStore.updateOwnerPrivilege(tSentryAuthorizable, roleName1, SentryPrincipalType.ROLE, null);
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1)
            .size());

    // At this point  roleName1 has owner privilege on db1.tb2
    //Add all privilege to roleName1 and make sure that owner privilege is not effected.
    TSentryPrivilege privilege_tbl2_all = new TSentryPrivilege(privilege_tbl2);
    privilege_tbl2_all.setAction(AccessConstants.ALL);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl2_all), null);
    // Verify that there are two privileges.
    assertEquals(2, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1)
            .size());


    tSentryAuthorizable.setTable("tbl3");
    TSentryPrivilege privilege_tbl3_all = new TSentryPrivilege(privilege_tbl2);
    privilege_tbl3_all.setAction(AccessConstants.ALL);
    privilege_tbl3_all.setTableName("tbl3");
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName3, Sets.newHashSet(privilege_tbl3_all), null);
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByRoleName(roleName3)
            .size());
    TSentryPrivilege privilege_tbl3_owner = new TSentryPrivilege(privilege_tbl3_all);
    privilege_tbl3_owner.setAction(AccessConstants.OWNER);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName3, Sets.newHashSet(privilege_tbl3_owner), null);

    assertEquals(2, sentryStore.getAllTSentryPrivilegesByRoleName(roleName3)
            .size());
  }

  @Test
  public void testListSentryOwnerPrivilegesByAuthorizable() throws Exception {
    String roleName1 = "list-privs-r1";
    String userName1 = "user1";
    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryUser(userName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction("OWNER");
    privilege_tbl1.setGrantOption(TSentryGrantOption.TRUE);

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer("server1");
    tSentryAuthorizable.setDb("db1");
    tSentryAuthorizable.setTable("tbl1");

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1), null);

    sentryStore.updateOwnerPrivilege(tSentryAuthorizable, userName1, SentryPrincipalType.USER, null);
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByUserName(userName1)
            .size());
  }

  @Test
  public void testRevokeOwnerPrivilege() throws Exception {

    String roleName1 = "list-privs-r1";
    String userName1 = "user1";
    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryUser(userName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction("OWNER");
    privilege_tbl1.setGrantOption(TSentryGrantOption.TRUE);

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer("server1");
    tSentryAuthorizable.setDb("db1");
    tSentryAuthorizable.setTable("tbl1");

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1), null);

    sentryStore.revokeOwnerPrivileges(tSentryAuthorizable, null);
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByUserName(userName1)
            .size());
  }


  @Test
  public void testgetPrivilegesForAuthorizables() throws Exception {

    String roleName1 = "list-privs-r1";
    String userName1 = "user1";
    String uri1 = "file:///var/folders/dt/9zm44z9s6bjfxbrm4v36lzdc0000gp/T/1401860678102-0/data/kv1.dat";

    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryUser(userName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction("SELECT");
    privilege_tbl1.setGrantOption(TSentryGrantOption.TRUE);

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer("server1");
    tSentryAuthorizable.setDb("db1");
    tSentryAuthorizable.setTable("tbl1");


    TSentryPrivilege privilege_tbl2 = new TSentryPrivilege();
    privilege_tbl2.setPrivilegeScope("TABLE");
    privilege_tbl2.setServerName("server1");
    privilege_tbl2.setDbName("db1");
    privilege_tbl2.setTableName("tbl2");
    privilege_tbl2.setCreateTime(System.currentTimeMillis());
    privilege_tbl2.setAction("SELECT");
    privilege_tbl2.setGrantOption(TSentryGrantOption.TRUE);

    TSentryAuthorizable tSentryAuthorizable2 = new TSentryAuthorizable();
    tSentryAuthorizable2.setServer("server1");
    tSentryAuthorizable2.setDb("db1");
    tSentryAuthorizable2.setTable("tbl2");

    TSentryPrivilege privilege_col1 = new TSentryPrivilege(privilege_tbl2);
    privilege_col1.setPrivilegeScope("TABLE");
    privilege_col1.setServerName("server1");
    privilege_col1.setDbName("db3");
    privilege_col1.setTableName("tbl3");
    privilege_col1.setCreateTime(System.currentTimeMillis());
    privilege_col1.setAction("SELECT");
    privilege_col1.setGrantOption(TSentryGrantOption.TRUE);
    privilege_col1.setColumnName("Column1");

    TSentryAuthorizable tSentryAuthorizable3 = new TSentryAuthorizable();
    tSentryAuthorizable3.setServer("server1");
    tSentryAuthorizable3.setDb("db3");
    tSentryAuthorizable3.setTable("tbl3");
    tSentryAuthorizable3.setColumn("Column1");

    TSentryPrivilege tSentryUriPrivilege = new TSentryPrivilege("URI", "server1", "ALL");
    tSentryUriPrivilege.setURI(uri1);

    TSentryAuthorizable tSentryUriAuthorizable = new TSentryAuthorizable();
    tSentryUriAuthorizable.setUri(uri1);
    tSentryUriAuthorizable.setServer("server1");


    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1,privilege_tbl2, privilege_col1, tSentryUriPrivilege), null);

    // Verify the privilege count
    List<MSentryPrivilege> privilege = sentryStore.getPrivilegesForAuthorizables(Lists.newArrayList(tSentryAuthorizable,tSentryAuthorizable2, tSentryUriAuthorizable, tSentryAuthorizable3));
    assertEquals(4, privilege.size());

   // Verify the behavior when the empty authorizable list provided.
   privilege = sentryStore.getPrivilegesForAuthorizables(Collections.EMPTY_LIST);
   assertNotNull(privilege);
   assertEquals(4, privilege.size());

    // Verify the behvaior when the authorizable list is null.
    privilege = sentryStore.getPrivilegesForAuthorizables(null);
    assertNotNull(privilege);
    assertEquals(4, privilege.size());

    // Verify the privilege granted to URI is returned
    privilege = sentryStore.getPrivilegesForAuthorizables(Lists.newArrayList(tSentryAuthorizable2));
    assertEquals(1, privilege.size());


    TSentryAuthorizable tSentrDbAuthorizable = new TSentryAuthorizable();
    tSentrDbAuthorizable.setServer("server1");
    tSentrDbAuthorizable.setDb("db1");

    // Verify that all the privileges granted to tables in database db1 are returned.
    privilege = sentryStore.getPrivilegesForAuthorizables(Lists.newArrayList(tSentrDbAuthorizable));
    assertEquals(2, privilege.size());


    // Verify that all the privileges granted to server are returned.
    privilege = sentryStore.getPrivilegesForAuthorizables(Lists.newArrayList(tSentryAuthorizable3));
    assertEquals(1, privilege.size());

    TSentryAuthorizable tSentrServerAuthorizable = new TSentryAuthorizable();
    tSentrServerAuthorizable.setServer("server1");

    // Verify that all the privileges granted to server are returned.
    privilege = sentryStore.getPrivilegesForAuthorizables(Lists.newArrayList(tSentrServerAuthorizable));
    assertEquals(4, privilege.size());

    // Grant user1 same privileges granted to role1 and make sure that there are no duplicates in the privileges.
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName1, Sets.newHashSet(privilege_tbl1,privilege_tbl2, tSentryUriPrivilege), null);

    // Verify that all the privileges granted to server are returned.
    privilege = sentryStore.getPrivilegesForAuthorizables(Lists.newArrayList(tSentrServerAuthorizable));
    assertEquals(4, privilege.size());
  }

  @Test
  public void testTranslatePrivileges() throws Exception {
    String roleName1 = "list-privs-r1";
    String userName1 = "user1";
    String uri1 = "file:///var/folders/dt/9zm44z9s6bjfxbrm4v36lzdc0000gp/T/1401860678102-0/data/kv1.dat";

    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryUser(userName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction("SELECT");
    privilege_tbl1.setGrantOption(TSentryGrantOption.TRUE);

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer("server1");
    tSentryAuthorizable.setDb("db1");
    tSentryAuthorizable.setTable("tbl1");


    TSentryPrivilege privilege_tbl2 = new TSentryPrivilege();
    privilege_tbl2.setPrivilegeScope("TABLE");
    privilege_tbl2.setServerName("server1");
    privilege_tbl2.setDbName("db1");
    privilege_tbl2.setTableName("tbl2");
    privilege_tbl2.setCreateTime(System.currentTimeMillis());
    privilege_tbl2.setAction("SELECT");
    privilege_tbl2.setGrantOption(TSentryGrantOption.TRUE);

    TSentryAuthorizable tSentryAuthorizable2 = new TSentryAuthorizable();
    tSentryAuthorizable2.setServer("server1");
    tSentryAuthorizable2.setDb("db1");
    tSentryAuthorizable2.setTable("tbl2");

    TSentryPrivilege privilege_col1 = new TSentryPrivilege(privilege_tbl2);
    privilege_col1.setPrivilegeScope("TABLE");
    privilege_col1.setServerName("server1");
    privilege_col1.setDbName("db3");
    privilege_col1.setTableName("tbl3");
    privilege_col1.setCreateTime(System.currentTimeMillis());
    privilege_col1.setAction("SELECT");
    privilege_col1.setGrantOption(TSentryGrantOption.TRUE);
    privilege_col1.setColumnName("Column1");

    TSentryAuthorizable tSentryAuthorizable3 = new TSentryAuthorizable();
    tSentryAuthorizable3.setServer("server1");
    tSentryAuthorizable3.setDb("db3");
    tSentryAuthorizable3.setTable("tbl3");
    tSentryAuthorizable3.setColumn("Column1");

    TSentryPrivilege tSentryUriPrivilege = new TSentryPrivilege("URI", "server1", "ALL");
    tSentryUriPrivilege.setURI(uri1);

    TSentryAuthorizable tSentryUriAuthorizable = new TSentryAuthorizable();
    tSentryUriAuthorizable.setUri(uri1);
    tSentryUriAuthorizable.setServer("server1");


    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1,privilege_tbl2, privilege_col1, tSentryUriPrivilege), null);

    // Grant user1 same privileges granted to role1 and make sure that there are no duplicates in the privileges.
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName1, Sets.newHashSet(privilege_tbl1,privilege_tbl2, tSentryUriPrivilege), null);

    Map<TSentryAuthorizable, Map<TPrivilegePrincipal, List<TPrivilege>>> mapping = sentryStore.getPrivilegesMap(null, null);

    assertNotNull(mapping);
    assertEquals(4, mapping.size());

    TSentryAuthorizable authorizable = new TSentryAuthorizable();
    TPrivilegePrincipal rolePrincipal = new TPrivilegePrincipal();
    rolePrincipal.setType(TPrivilegePrincipalType.ROLE);
    rolePrincipal.setValue(roleName1);
    TPrivilegePrincipal userPrincipal = new TPrivilegePrincipal();
    userPrincipal.setType(TPrivilegePrincipalType.USER);
    userPrincipal.setValue(userName1);
    authorizable.setServer("server1");
    authorizable.setDb("db1");
    authorizable.setTable("tbl1");
    authorizable.setUri("");
    authorizable.setColumn("");
  //  TPrivilege tPrivilege = new TPrivilege();
    assertTrue(mapping.containsKey(authorizable));
    assertEquals(2, mapping.get(authorizable).size());
    assertEquals(1, mapping.get(authorizable).get(rolePrincipal).size());
//    assertTrue(mapping.get(authorizable).get(rolePrincipal).contains("select"));
    assertEquals(1, mapping.get(authorizable).get(userPrincipal).size());
//    assertTrue(mapping.get(authorizable).get(userPrincipal).contains("select"));

    authorizable.setTable("tbl2");
    assertTrue(mapping.containsKey(authorizable));
    assertEquals(2, mapping.get(authorizable).size());
    assertEquals(1, mapping.get(authorizable).get(rolePrincipal).size());
//    assertTrue(mapping.get(authorizable).get(rolePrincipal).contains("select"));
    assertEquals(1, mapping.get(authorizable).get(userPrincipal).size());
//    assertTrue(mapping.get(authorizable).get(userPrincipal).contains("select"));

    authorizable.setDb("db3");
    authorizable.setTable("tbl3");
    authorizable.setColumn("column1");
    assertTrue(mapping.containsKey(authorizable));
    assertEquals(1, mapping.get(authorizable).size());
    assertEquals(1, mapping.get(authorizable).get(rolePrincipal).size());
//    assertTrue(mapping.get(authorizable).get(rolePrincipal).contains("select"));

    authorizable.clear();
    authorizable.setDb("");
    authorizable.setTable("");
    authorizable.setColumn("");
    authorizable.setServer("server1");

    authorizable.setUri(uri1);

    assertTrue(mapping.containsKey(authorizable));
    assertEquals(2, mapping.get(authorizable).size());
    assertEquals(1, mapping.get(authorizable).get(rolePrincipal).size());
//    assertTrue(mapping.get(authorizable).get(rolePrincipal).contains("all"));
    assertEquals(1, mapping.get(authorizable).get(userPrincipal).size());
//    assertTrue(mapping.get(authorizable).get(userPrincipal).contains("all"));

  }

  @Test
  public void testgetPrivilegesForURIs() throws Exception {

    String roleName1 = "list-privs-r1";
    String uriPrefix = "file:///var/folders/dt/9zm44z9s6bjfxbrm4v36lzdc0000gp/T/1401860678102-0/";
    String uri1 = "file:///var/folders/dt/9zm44z9s6bjfxbrm4v36lzdc0000gp/T/1401860678102-0/data/kv1.dat";
    String uri2 = "file:///var/folders/dt/9zm44z9s6bjfxbrm4v36lzdc0000gp/T/1401860678102-0/data/kv2.dat";


    sentryStore.createSentryRole(roleName1);

    TSentryPrivilege tSentryUriPrivilege1 = new TSentryPrivilege("URI", "server1", "ALL");
    tSentryUriPrivilege1.setURI(uri1);

    TSentryPrivilege tSentryUriPrivilege2 = new TSentryPrivilege("URI", "server1", "ALL");
    tSentryUriPrivilege2.setURI(uri2);

    TSentryAuthorizable tSentryUriAuthorizable = new TSentryAuthorizable();
    tSentryUriAuthorizable.setUri(uriPrefix);
    tSentryUriAuthorizable.setServer("server1");


    // Grant user1 same privileges granted to role1 and make sure that there are no duplicates in the privileges.
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(tSentryUriPrivilege1, tSentryUriPrivilege2), null);

    // Verify that all the privileges granted to all the URI;s under given prefix are returned.
    List<MSentryPrivilege> privilege = sentryStore.getPrivilegesForAuthorizables(Lists.newArrayList(tSentryUriAuthorizable));
    assertEquals(2, privilege.size());
  }

  @Test
  public void testDropUserOnUpdateOwnerPrivilege() throws Exception {
    String userName1 = "user1", userName2 = "user2";
    sentryStore.createSentryUser(userName1);
    sentryStore.createSentryUser(userName2);


    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction("OWNER");

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer("server1");
    tSentryAuthorizable.setDb("db1");
    tSentryAuthorizable.setTable("tbl1");


    // Change owner from a one user to another user
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName1, Sets.newHashSet(privilege_tbl1), null);
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByUserName(userName1)
            .size());


    sentryStore.updateOwnerPrivilege(tSentryAuthorizable, userName2, SentryPrincipalType.USER, null);
    assertEquals(1, sentryStore.getAllTSentryPrivilegesByUserName(userName2)
            .size());

    try {
      sentryStore.createSentryUser(userName1);
    } catch (Exception e) {
      fail("Exception should not be seen asthe user: " + userName1 + " should have been deleted.");
    }

  }
  /**
   * Regression test for SENTRY-547 and SENTRY-548
   * Use case:
   * GRANT INSERT on TABLE tbl1 to ROLE role1
   * GRANT SELECT on TABLE tbl1 to ROLE role1
   * GRANT ALTER on TABLE tbl1 to ROLE role1
   * GRANT DROP on TABLE tbl1 to ROLE role1
   * DROP TABLE tbl1
   *
   * After drop tbl1, role1 should have 0 privileges
   */
  @Test
  public void testDropTableWithMultiAction() throws Exception {
    String roleName1 = "role1";
    sentryStore.createSentryRole(roleName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_insert = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_insert.setAction(AccessConstants.INSERT);

    TSentryPrivilege privilege_tbl1_select = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_select.setAction(AccessConstants.SELECT);

    TSentryPrivilege privilege_tbl1_alter = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_alter.setAction(AccessConstants.ALTER);

    TSentryPrivilege privilege_tbl1_drop = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_drop.setAction(AccessConstants.DROP);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_insert), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_select), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_alter), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_drop), null);

    assertEquals(4, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1).size());

    // after drop privilege_tbl1, role1 should have 0 privileges
    sentryStore.dropPrivilege(toTSentryAuthorizable(privilege_tbl1));
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1).size());
  }

  @Test
  public void testDropTableWithColumn() throws Exception {
    String roleName1 = "role1", roleName2 = "role2";
    String table1 = "tbl1";

    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName(table1);
    privilege_tbl1.setAction(AccessConstants.SELECT);
    privilege_tbl1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_c1 = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_c1.setPrivilegeScope("COLUMN");
    privilege_tbl1_c1.setColumnName("c1");
    privilege_tbl1_c1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_c2 = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_c2.setPrivilegeScope("COLUMN");
    privilege_tbl1_c2.setColumnName("c2");
    privilege_tbl1_c2.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_c3 = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_c3.setPrivilegeScope("COLUMN");
    privilege_tbl1_c3.setColumnName("c3");
    privilege_tbl1_c3.setCreateTime(System.currentTimeMillis());

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_c1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_c2), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege_tbl1_c3), null);

    Set<TSentryPrivilege> privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName1);
    assertEquals(2, privilegeSet.size());
    privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName2);
    assertEquals(1, privilegeSet.size());

    TSentryAuthorizable tableAuthorizable = toTSentryAuthorizable(privilege_tbl1);
    sentryStore.dropPrivilege(tableAuthorizable);

    privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName1);
    assertEquals(0, privilegeSet.size());
    privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName2);
    assertEquals(0, privilegeSet.size());
  }

  @Test
  public void testDropOverlappedPrivileges() throws Exception {
    String roleName1 = "list-privs-r1";
    sentryStore.createSentryRole(roleName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_insert = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_insert.setAction("INSERT");

    TSentryPrivilege privilege_tbl1_all = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_all.setAction("*");

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_insert), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_all), null);

    sentryStore.dropPrivilege(toTSentryAuthorizable(privilege_tbl1));
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1)
        .size());
  }

  private TSentryAuthorizable toTSentryAuthorizable(
      TSentryPrivilege tSentryPrivilege) {
    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer(tSentryPrivilege.getServerName());
    tSentryAuthorizable.setDb(tSentryPrivilege.getDbName());
    tSentryAuthorizable.setTable(tSentryPrivilege.getTableName());
    tSentryAuthorizable.setUri(tSentryPrivilege.getURI());
    return tSentryAuthorizable;
  }

  /***
   * Create roles and users and assign privileges for same table rename the privileges for
   * the table and verify the new privileges
   * @throws Exception
   */
  @Test
  public void testRenameTable() throws Exception {
    String roleName1 = "role1", roleName2 = "role2", roleName3 = "role3";
    String userName1 = "user-1", userName2 = "user-2", userName3 = "user-3";
    String table1 = "tbl1", table2 = "tbl2";

    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);
    sentryStore.createSentryRole(roleName3);
    sentryStore.createSentryUser(userName1);
    sentryStore.createSentryUser(userName2);
    sentryStore.createSentryUser(userName3);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName(table1);
    privilege_tbl1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_insert = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_insert.setAction(AccessConstants.INSERT);

    TSentryPrivilege privilege_tbl1_select = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_select.setAction(AccessConstants.SELECT);

    TSentryPrivilege privilege_tbl1_all = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_all.setAction(AccessConstants.ALL);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_insert), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege_tbl1_select), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName3, Sets.newHashSet(privilege_tbl1_all), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName1, Sets.newHashSet(privilege_tbl1_insert), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName2, Sets.newHashSet(privilege_tbl1_select), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName3, Sets.newHashSet(privilege_tbl1_all), null);

    TSentryAuthorizable oldTable = toTSentryAuthorizable(privilege_tbl1);
    TSentryAuthorizable newTable = toTSentryAuthorizable(privilege_tbl1);
    newTable.setTable(table2);
    sentryStore.renamePrivilege(oldTable, newTable);

    for (String roleName : Sets.newHashSet(roleName1, roleName2, roleName3)) {
      Set<TSentryPrivilege> privilegeSet = sentryStore
          .getAllTSentryPrivilegesByRoleName(roleName);
      assertEquals(1, privilegeSet.size());
      for (TSentryPrivilege privilege : privilegeSet) {
        assertTrue(table2.equalsIgnoreCase(privilege.getTableName()));
      }
    }
    for (String userName : Sets.newHashSet(userName1, userName2, userName3)) {
      Set<TSentryPrivilege> privilegeSet = sentryStore
              .getAllTSentryPrivilegesByUserName(userName);
      assertEquals(1, privilegeSet.size());
      for (TSentryPrivilege privilege : privilegeSet) {
        assertTrue(table2.equalsIgnoreCase(privilege.getTableName()));
      }
    }
  }

  /**
   * Regression test for SENTRY-550
   * Use case:
   * GRANT INSERT on TABLE tbl1 to ROLE role1
   * GRANT SELECT on TABLE tbl1 to ROLE role1
   * GRANT ALTER on TABLE tbl1 to ROLE role1
   * GRANT DROP on TABLE tbl1 to ROLE role1
   * RENAME TABLE tbl1 to tbl2
   *
   * After rename tbl1 to tbl2, table name of all role1's privileges should be "tbl2"
   */
  @Test
  public void testRenameTableWithMultiAction() throws Exception {
    String roleName1 = "role1";
    String table1 = "tbl1", table2 = "tbl2";
    sentryStore.createSentryRole(roleName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName(table1);
    privilege_tbl1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_insert = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_insert.setAction(AccessConstants.INSERT);

    TSentryPrivilege privilege_tbl1_select = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_select.setAction(AccessConstants.SELECT);

    TSentryPrivilege privilege_tbl1_alter = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_alter.setAction(AccessConstants.ALTER);

    TSentryPrivilege privilege_tbl1_drop = new TSentryPrivilege(
        privilege_tbl1);
    privilege_tbl1_drop.setAction(AccessConstants.DROP);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_insert), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_select), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_alter), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_drop), null);

    TSentryAuthorizable oldTable = toTSentryAuthorizable(privilege_tbl1);
    TSentryAuthorizable newTable = toTSentryAuthorizable(privilege_tbl1);
    newTable.setTable(table2);
    sentryStore.renamePrivilege(oldTable, newTable);

    // after rename tbl1 to tbl2, all table name of role's privilege will be tbl2
    Set<TSentryPrivilege> privilegeSet = sentryStore
        .getAllTSentryPrivilegesByRoleName(roleName1);
    assertEquals(4, privilegeSet.size());
    for (TSentryPrivilege privilege : privilegeSet) {
      assertTrue(table2.equalsIgnoreCase(privilege.getTableName()));
    }
  }

  @Test
  public void testSentryRoleSize() throws Exception {
    for( long i = 0; i< 5; i++ ) {
      assertEquals((Long)i, sentryStore.getRoleCountGauge().getValue());
      sentryStore.createSentryRole("role" + i);
    }
  }
  @Test
  public void testSentryPrivilegeSize() throws Exception {
    String role1 = "role1";
    String role2 = "role2";

    sentryStore.createSentryRole(role1);
    sentryStore.createSentryRole(role2);

    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName("server1");
    privilege.setDbName("db1");
    privilege.setTableName("tb1");
    privilege.setCreateTime(System.currentTimeMillis());

    assertEquals(Long.valueOf(0), sentryStore.getPrivilegeCountGauge().getValue());

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, role1, Sets.newHashSet(privilege), null);
    assertEquals(Long.valueOf(1), sentryStore.getPrivilegeCountGauge().getValue());

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, role2, Sets.newHashSet(privilege), null);
    assertEquals(Long.valueOf(1), sentryStore.getPrivilegeCountGauge().getValue());

    privilege.setTableName("tb2");
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, role2, Sets.newHashSet(privilege), null);
    assertEquals(Long.valueOf(2), sentryStore.getPrivilegeCountGauge().getValue());
  }

  @Test
  public void testSentryGroupsSize() throws Exception {
    String role1 = "role1";
    String role2 = "role2";

    sentryStore.createSentryRole(role1);
    sentryStore.createSentryRole(role2);

    Set<TSentryGroup> groups = Sets.newHashSet();
    TSentryGroup group = new TSentryGroup();
    group.setGroupName("group1");
    groups.add(group);

    String grantor = "g1";

    sentryStore.alterSentryRoleAddGroups(grantor, role1, groups);
    assertEquals(Long.valueOf(1), sentryStore.getGroupCountGauge().getValue());

    sentryStore.alterSentryRoleAddGroups(grantor, role2, groups);
    assertEquals(Long.valueOf(1), sentryStore.getGroupCountGauge().getValue());

    groups.add(new TSentryGroup("group2"));
    sentryStore.alterSentryRoleAddGroups(grantor, role2, groups);
    assertEquals(Long.valueOf(2), sentryStore.getGroupCountGauge().getValue());

  }

  @Test
  public void testSentryUsersSize() throws Exception {
    String role1 = "role1";
    String role2 = "role2";

    sentryStore.createSentryRole(role1);
    sentryStore.createSentryRole(role2);

    Set<String> users = Sets.newHashSet("user1");

    sentryStore.alterSentryRoleAddUsers(role1, users);
    assertEquals(Long.valueOf(1), sentryStore.getUserCountGauge().getValue());

    sentryStore.alterSentryRoleAddUsers(role2, users);
    assertEquals(Long.valueOf(1), sentryStore.getUserCountGauge().getValue());

    users.add("user2");
    sentryStore.alterSentryRoleAddUsers(role2, users);
    assertEquals(Long.valueOf(2), sentryStore.getUserCountGauge().getValue());

  }

  @Test
  public void testRenameTableWithColumn() throws Exception {
    String roleName1 = "role1", roleName2 = "role2";
    String table1 = "tbl1", table2 = "tbl2";

    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName(table1);
    privilege_tbl1.setAction(AccessConstants.SELECT);
    privilege_tbl1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_c1 = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_c1.setPrivilegeScope("COLUMN");
    privilege_tbl1_c1.setColumnName("c1");
    privilege_tbl1_c1.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_c2 = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_c2.setPrivilegeScope("COLUMN");
    privilege_tbl1_c2.setColumnName("c2");
    privilege_tbl1_c2.setCreateTime(System.currentTimeMillis());

    TSentryPrivilege privilege_tbl1_c3 = new TSentryPrivilege(privilege_tbl1);
    privilege_tbl1_c3.setPrivilegeScope("COLUMN");
    privilege_tbl1_c3.setColumnName("c3");
    privilege_tbl1_c3.setCreateTime(System.currentTimeMillis());

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_c1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1_c2), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege_tbl1_c3), null);

    Set<TSentryPrivilege> privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName1);
    assertEquals(2, privilegeSet.size());
    privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName2);
    assertEquals(1, privilegeSet.size());

    TSentryAuthorizable oldTable = toTSentryAuthorizable(privilege_tbl1);
    TSentryAuthorizable newTable = toTSentryAuthorizable(privilege_tbl1);
    newTable.setTable(table2);
    sentryStore.renamePrivilege(oldTable, newTable);

    privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName1);
    assertEquals(2, privilegeSet.size());
    for (TSentryPrivilege privilege : privilegeSet) {
      assertTrue(table2.equalsIgnoreCase(privilege.getTableName()));
    }
    privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName2);
    assertEquals(1, privilegeSet.size());
  }

  @Test
  public void testSentryTablePrivilegeSome() throws Exception {
    String roleName = "test-table-privilege-some";
    String grantor = "g1";
    String dbName = "db1";
    String table = "tb1";
    createRole(roleName);
    TSentryPrivilege tSentryPrivilege = new TSentryPrivilege("TABLE", "server1", "ALL");
    tSentryPrivilege.setDbName(dbName);
    tSentryPrivilege.setTableName(table);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(tSentryPrivilege), null);

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setDb(dbName);
    tSentryAuthorizable.setTable(AccessConstants.SOME);
    tSentryAuthorizable.setServer("server1");

    Set<TSentryPrivilege> privileges =
        sentryStore.getTSentryPrivileges(SentryPrincipalType.ROLE, new HashSet<String>(Arrays.asList(roleName)), tSentryAuthorizable);

    assertTrue(privileges.size() == 1);

    Set<TSentryGroup> tSentryGroups = new HashSet<TSentryGroup>();
    tSentryGroups.add(new TSentryGroup("group1"));
    sentryStore.alterSentryRoleAddGroups(grantor, roleName, tSentryGroups);

    TSentryActiveRoleSet thriftRoleSet = new TSentryActiveRoleSet(true, new HashSet<String>(Arrays.asList(roleName)));

    Set<String> privs =
        sentryStore.listSentryPrivilegesForProvider(new HashSet<String>(Arrays.asList("group1")),
            Sets.newHashSet(grantor), thriftRoleSet, tSentryAuthorizable);

    assertTrue(privs.size()==1);
    assertTrue(privs.contains("server=server1->db=" + dbName + "->table=" + table + "->action=all"));

  }


  @Test
  public void testSentryColumnPrivilegeSome() throws Exception {
    String roleName = "test-column-privilege-some";
    String grantor = "g1";
    String dbName = "db1";
    String table = "tb1";
    String column = "col1";
    createRole(roleName);
    TSentryPrivilege tSentryPrivilege = new TSentryPrivilege("TABLE", "server1", "ALL");
    tSentryPrivilege.setDbName(dbName);
    tSentryPrivilege.setTableName(table);
    tSentryPrivilege.setColumnName(column);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(tSentryPrivilege), null);

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setDb(dbName);
    tSentryAuthorizable.setTable(table);
    tSentryAuthorizable.setColumn(AccessConstants.SOME);
    tSentryAuthorizable.setServer("server1");

    Set<TSentryPrivilege> privileges =
        sentryStore.getTSentryPrivileges(SentryPrincipalType.ROLE, new HashSet<String>(Arrays.asList(roleName)), tSentryAuthorizable);

    assertTrue(privileges.size() == 1);

    Set<TSentryGroup> tSentryGroups = new HashSet<TSentryGroup>();
    tSentryGroups.add(new TSentryGroup("group1"));
    sentryStore.alterSentryRoleAddGroups(grantor, roleName, tSentryGroups);

    TSentryActiveRoleSet thriftRoleSet = new TSentryActiveRoleSet(true, new HashSet<String>(Arrays.asList(roleName)));

    Set<String> privs =
        sentryStore.listSentryPrivilegesForProvider(new HashSet<String>(Arrays.asList("group1")), Sets.newHashSet(grantor),
                thriftRoleSet, tSentryAuthorizable);

    assertTrue(privs.size() == 1);
    assertTrue(privs.contains("server=server1->db=" + dbName + "->table=" + table + "->column="
        + column + "->action=all"));

  }

  @Test
  public void testSentryVersionCheck() throws Exception {
    // don't verify version, the current version willll be set in MSentryVersion
    sentryStore.verifySentryStoreSchema(false);
    assertEquals(sentryStore.getSentryVersion(),
        SentryStoreSchemaInfo.getSentryVersion());

    // verify the version with the same value
    sentryStore.verifySentryStoreSchema(true);

    // verify the version with the different value
    sentryStore.setSentryVersion("test-version", "test-version");
    try {
      sentryStore.verifySentryStoreSchema(true);
      fail("SentryAccessDeniedException should be thrown.");
    } catch (SentryAccessDeniedException e) {
      // the excepted exception, recover the version
      sentryStore.verifySentryStoreSchema(false);
    }
  }

  @Test
  public void testRetrieveFullPermssionsImage() throws Exception {

    // Create roles
    String roleName1 = "privs-r1", roleName2 = "privs-r2";
    String groupName1 = "privs-g1";
    String grantor = "g1";
    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);

    // Grant Privileges to the roles
    TSentryPrivilege privilege1 = new TSentryPrivilege();
    privilege1.setPrivilegeScope("TABLE");
    privilege1.setServerName("server1");
    privilege1.setDbName("db1");
    privilege1.setTableName("tbl1");
    privilege1.setAction("SELECT");
    privilege1.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege1), null);

    TSentryPrivilege privilege2 = new TSentryPrivilege();
    privilege2.setPrivilegeScope("SERVER");
    privilege2.setServerName("server1");
    privilege1.setDbName("db2");
    privilege1.setAction("ALL");
    privilege2.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege2), null);

    // Grant roles to the groups
    Set<TSentryGroup> groups = Sets.newHashSet();
    TSentryGroup group = new TSentryGroup();
    group.setGroupName(groupName1);
    groups.add(group);
    sentryStore.alterSentryRoleAddGroups(grantor, roleName1, groups);
    sentryStore.alterSentryRoleAddGroups(grantor, roleName2, groups);

    //Grant owner privilege to role
    TSentryPrivilege privilege3 = new TSentryPrivilege();
    privilege3.setPrivilegeScope("TABLE");
    privilege3.setServerName("server1");
    privilege3.setDbName("db3");
    privilege3.setTableName("tbl1");
    privilege3.setAction("OWNER");
    privilege3.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege3), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName2, Sets.newHashSet(privilege3), null);

    PermissionsImage permImage = sentryStore.retrieveFullPermssionsImage();
    Map<String, Map<TPrivilegePrincipal, String>> privs = permImage.getPrivilegeImage();
    Map<String, List<String>> roles = permImage.getRoleImage();
    assertEquals(2, privs.get("db1.tbl1").size());
    assertEquals(2, roles.size());

    assertEquals(2, privs.get("db3.tbl1").size());
    assertEquals("ALL", privs.get("db3.tbl1").get(new TPrivilegePrincipal(TPrivilegePrincipalType.ROLE, roleName1)));
    assertEquals("ALL", privs.get("db3.tbl1").get(new TPrivilegePrincipal(TPrivilegePrincipalType.ROLE, roleName2)));

  }

  /**
   * Verifies complete snapshot of HMS Paths can be persisted and retrieved properly.
   */
  @Test
  public void testPersistFullPathsImage() throws Exception {
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    String[] prefixes = {"/user/hive/warehouse"};
    // Makes sure that authorizable object could be associated
    // with different paths and can be properly persisted into database.
    authzPaths.put("db1.table1", Sets.newHashSet("/user/hive/warehouse/db2.db/table1.1",
        "/user/hive/warehouse/db2.db/table1.2"));
    // Makes sure that the same MPaths object could be associated
    // with multiple authorizable and can be properly persisted into database.
    authzPaths.put("db1.table2", Sets.newHashSet("/user/hive/warehouse/db2.db/table2.1",
        "/user/hive/warehouse/db2.db/table2.2"));
    authzPaths.put("db2.table2", Sets.newHashSet("/user/hive/warehouse/db2.db/table2.1",
        "/user/hive/warehouse/db2.db/table2.3"));
    long notificationID = 11;
    sentryStore.persistFullPathsImage(authzPaths, notificationID);
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    long savedNotificationID = sentryStore.getLastProcessedNotificationID();
    assertEquals(1, pathsUpdate.getImgNum());
    TPathsDump pathDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry> nodeMap = pathDump.getNodeMap();

    assertEquals(10, nodeMap.size());
    //First element is "/"
    int rootId = pathDump.getRootId();
    TPathEntry root = nodeMap.get(rootId);
    assertEquals("/", root.getPathElement());

    Map<String, Collection<String>>pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, true);

    assertEquals(3, pathImage.size());
    for (Map.Entry<String, Collection<String>> entry : pathImage.entrySet()) {
      assertEquals(2, entry.getValue().size());
    }
    assertEquals(2, pathImage.get("db2.table2").size());
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("/user/hive/warehouse/db2.db/table1.1",
        "/user/hive/warehouse/db2.db/table1.2"),
        pathImage.get("db1.table1")));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("/user/hive/warehouse/db2.db/table2.1",
        "/user/hive/warehouse/db2.db/table2.2"),
        pathImage.get("db1.table2")));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("/user/hive/warehouse/db2.db/table2.1",
        "/user/hive/warehouse/db2.db/table2.3"),
        pathImage.get("db2.table2")));
    assertEquals(6, sentryStore.getPathCount());
    assertEquals(notificationID, savedNotificationID);
  }

  @Test
  public void testAddAuthzPathsMapping() throws Exception {
    Set<MPath> paths;
    // Persist an empty image so that we can add paths to it.
    sentryStore.persistFullPathsImage(new HashMap<String, Collection<String>>(), 0);

    // Check the latest persisted ID matches to both the path updates
    long latestID = sentryStore.getCurrentAuthzPathsSnapshotID();


    // Persist the path
    sentryStore.addAuthzPathsMapping("db1.tb1", Arrays.asList("/hive/db1/tb1"), null);
    paths = sentryStore.getMAuthzPaths(latestID, "db1.tb1");
    // Verify that mapping is been added
    assertEquals(paths.size(), 1);
    assertTrue(paths.stream().anyMatch(x -> x.getPath().equalsIgnoreCase("/hive/db1/tb1")));

    // Add new path to an existing mapping
    sentryStore.addAuthzPathsMapping("db1.tb1", Arrays.asList("/hive/db1/tb1/par1"), null);
    paths = sentryStore.getMAuthzPaths(latestID, "db1.tb1");
    // Verify that mapping is been updated with the new path
    assertEquals(paths.size(), 2);
    assertTrue(paths.stream().anyMatch(x -> x.getPath().equalsIgnoreCase("/hive/db1/tb1/par1")));

    // Add multiples path to an existing mapping
    sentryStore.addAuthzPathsMapping("db1.tb1", Arrays.asList("/hive/db1/tb1/par2","/hive/db1/tb1/par3"), null);
    paths = sentryStore.getMAuthzPaths(latestID, "db1.tb1");
    // Verify that mapping is been updated with the new path
    assertEquals(paths.size(), 4);
    assertTrue(paths.stream().anyMatch(x -> x.getPath().equalsIgnoreCase("/hive/db1/tb1/par2")));
    assertTrue(paths.stream().anyMatch(x -> x.getPath().equalsIgnoreCase("/hive/db1/tb1/par3")));
  }

  @Test
  public void testAddPathsWithDuplicatedNotificationIdShouldBeAllowed() throws Exception {
    long notificationID = 1;

    // Persist an empty image so that we can add paths to it.
    sentryStore.persistFullPathsImage(new HashMap<String, Collection<String>>(), 0);

    // Create two path updates with the same sequence ID
    UniquePathsUpdate update1 = new UniquePathsUpdate("u1", notificationID, false);
    UniquePathsUpdate update2 = new UniquePathsUpdate("u2", notificationID, false);

    // Populate the path updates with different objects and paths
    update1.newPathChange("db1").addToAddPaths(Arrays.asList("/hive/db1"));
    update2.newPathChange("db2").addToAddPaths(Arrays.asList("/hive/db2"));

    // Persist both path updates. Persisting should be allowed, and paths should be
    // persisted even if they have the same sequence ID
    sentryStore.addAuthzPathsMapping("db1", Arrays.asList("/hive/db1"), update1);
    sentryStore.addAuthzPathsMapping("db2", Arrays.asList("/hive/db2"), update2);

    // Check the latest persisted ID matches to both the path updates
    long latestID = sentryStore.getLastProcessedNotificationID();
    assertEquals(notificationID, latestID);

    String []prefixes = {"/hive"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry> nodeMap = pathDump.getNodeMap();
    assertEquals(4, nodeMap.size());
    int rootId = pathDump.getRootId();
    TPathEntry root = nodeMap.get(rootId);
    assertEquals("/", root.getPathElement());

    Map<String, Collection<String>>pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, true);

    // Check that retrieving a full paths image returns both paths updates
    assertEquals(2, pathsImage.size());
    assertEquals(1, pathsImage.get("db1").size());
    assertTrue(pathsImage.get("db1").contains("/hive/db1"));
    assertEquals(1, pathsImage.get("db2").size());
    assertTrue(pathsImage.get("db2").contains("/hive/db2"));

    // Check that retrieving delta changes returns both patch updates
    List<MSentryPathChange> pathsChanges = sentryStore.getMSentryPathChanges();
    assertEquals(2, pathsChanges.size());
    assertEquals(1, pathsChanges.get(0).getChangeID()); // changeID = 1
    assertTrue(pathsChanges.get(0).getPathChange().contains("/hive/db1"));
    assertEquals(2, pathsChanges.get(1).getChangeID()); // changeID = 2
    assertTrue(pathsChanges.get(1).getPathChange().contains("/hive/db2"));

    // Check that the SHA1 hash calculated for unique notifications is correct
    assertEquals("u1", pathsChanges.get(0).getNotificationHash());
    assertEquals("u2", pathsChanges.get(1).getNotificationHash());
  }

  private void buildPathsImageMap(Map<Integer, TPathEntry> nodeMap, TPathEntry node, String path,
      Map<String, Collection<String>> pathsImage, boolean includeLeadingSlash) {
    path = path.isEmpty()?node.getPathElement(): (path + node.getPathElement() + "/");
    TPathEntry tempNode = node;
    for(int childVal:node.getChildren()) {
      node = nodeMap.get(childVal);
      buildPathsImageMap(nodeMap, node, path, pathsImage, includeLeadingSlash);
    }
    if(tempNode.getChildren().isEmpty() && node.getAuthzObjs() != null) {
      for (String authz : node.getAuthzObjs()) {
        if (!pathsImage.containsKey(authz)) {
          pathsImage.put(authz, new LinkedList<>());
        }
        if(includeLeadingSlash) {
          pathsImage.get(authz).add(path.replaceAll("(/+$)", ""));
        } else {
          pathsImage.get(authz).add(path.replaceAll("(^/+)|(/+$)", ""));
        }
      }
    }
  }

  @Test
  public void testPersistDuplicatedNotificationIdShouldBeAllowed() throws Exception {
    long notificationID = 1;

    // Persist the same ID twice should not cause any issues
    sentryStore.persistLastProcessedNotificationID(notificationID);
    sentryStore.persistLastProcessedNotificationID(notificationID);

    // Retrieving latest peristed ID should match with the previous persisted ID
    long latestID = sentryStore.getLastProcessedNotificationID();
    assertEquals(notificationID, latestID);
  }

  @Test
  public void testAddDeleteAuthzPathsMapping() throws Exception {
    long notificationID = 0;

    // Persist an empty image so that we can add paths to it.
    sentryStore.persistFullPathsImage(new HashMap<String, Collection<String>>(), notificationID);

    // Add "db1.table1" authzObj
    Long lastNotificationId = sentryStore.getLastProcessedNotificationID();
    UniquePathsUpdate addUpdate = new UniquePathsUpdate("u1", 1, false);
    addUpdate.newPathChange("db1.table").
          addToAddPaths(Arrays.asList("db1", "tbl1"));
    addUpdate.newPathChange("db1.table").
          addToAddPaths(Arrays.asList("db1", "tbl2"));

    sentryStore.addAuthzPathsMapping("db1.table",
          Sets.newHashSet("db1/tbl1", "db1/tbl2"), addUpdate);
    String[]prefixes = {"/"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals(4, nodeMap.size());//Tree size
    assertEquals("/", root.getPathElement());
    assertEquals(1, pathImage.size());
    assertEquals(2, pathImage.get("db1.table").size());
    assertEquals(2, sentryStore.getMPaths().size());

    // Query the persisted path change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPathChangeID();
    MSentryPathChange addPathChange = sentryStore.getMSentryPathChangeByID(lastChangeID);
    assertEquals(addUpdate.JSONSerialize(), addPathChange.getPathChange());
    lastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(1, lastNotificationId.longValue());

    // Delete path 'db1.db/tbl1' from "db1.table1" authzObj.
    UniquePathsUpdate delUpdate = new UniquePathsUpdate("u2",2, false);
    delUpdate.newPathChange("db1.table")
          .addToDelPaths(Arrays.asList("db1", "tbl1"));
    sentryStore.deleteAuthzPathsMapping("db1.table", Sets.newHashSet("db1/tbl1"), delUpdate);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(3, nodeMap.size());//Tree size
    assertEquals(1, pathImage.size());
    assertEquals(1, pathImage.get("db1.table").size());
    assertEquals(1, sentryStore.getMPaths().size());

    // Query the persisted path change and ensure it equals to the original one
    lastChangeID = sentryStore.getLastProcessedPathChangeID();
    MSentryPathChange delPathChange = sentryStore.getMSentryPathChangeByID(lastChangeID);
    assertEquals(delUpdate.JSONSerialize(), delPathChange.getPathChange());
    lastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(2, lastNotificationId.longValue());

    // Delete "db1.table" authzObj from the authzObj -> [Paths] mapping.
    UniquePathsUpdate delAllupdate = new UniquePathsUpdate("u3",3, false);
    delAllupdate.newPathChange("db1.table")
        .addToDelPaths(Lists.newArrayList(PathsUpdate.ALL_PATHS));
    sentryStore.deleteAllAuthzPathsMapping("db1.table", delAllupdate);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(1, nodeMap.size());//Tree size
    assertEquals(0, pathImage.size());
    assertEquals(0, sentryStore.getMPaths().size());
    assertEquals(0, sentryStore.getCount(MPath.class).intValue());

    // Query the persisted path change and ensure it equals to the original one
    lastChangeID = sentryStore.getLastProcessedPathChangeID();
    MSentryPathChange delAllPathChange = sentryStore.getMSentryPathChangeByID(lastChangeID);
    assertEquals(delAllupdate.JSONSerialize(), delAllPathChange.getPathChange());

    lastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(3, lastNotificationId.longValue());

  }

  @Test
  public void testDeleteAuthzPathsMapping() throws Exception {

    long notificationID = 0;

    // Persist an empty image so that we can add paths to it.
    sentryStore.persistFullPathsImage(new HashMap<String, Collection<String>>(), notificationID);

    // Add a mapping to two paths
    sentryStore.addAuthzPathsMapping("db1.table",
            Sets.newHashSet("db1/tbl1", "db1/tbl2"), null);

    // Verify the Path count
    assertEquals(2, sentryStore.getCount(MPath.class).intValue());

    // Add a mapping to three paths
    sentryStore.addAuthzPathsMapping("db2.table",
            Sets.newHashSet("db2/tbl1", "db2/tbl2", "db2/tbl3"), null);


    // Verify the Path count
    assertEquals(5, sentryStore.getCount(MPath.class).intValue());

    // deleting the mapping and verifying the MPath count
    sentryStore.deleteAllAuthzPathsMapping("db1.table", null);
   // Verify the Path count
    assertEquals(3, sentryStore.getCount(MPath.class).intValue());


    // deleting the mapping and verifying the MPath count
    sentryStore.deleteAllAuthzPathsMapping("db2.table", null);
    // Verify the Path count
    assertEquals(0, sentryStore.getCount(MPath.class).intValue());
  }

  @Test
  public void testRenameUpdateAuthzPathsMapping() throws Exception {
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    Long lastNotificationId = sentryStore.getLastProcessedNotificationID();
    authzPaths.put("db1.table1", Sets.newHashSet("user/hive/warehouse/db1.db/table1",
                                                "user/hive/warehouse/db1.db/table1/p1"));
    authzPaths.put("db1.table2", Sets.newHashSet("user/hive/warehouse/db1.db/table2"));
    sentryStore.persistFullPathsImage(authzPaths, lastNotificationId);
    String[]prefixes = {"/user/hive/warehouse"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(8, nodeMap.size());//Tree size
    assertEquals(2, pathsImage.size());


    // Rename path of 'db1.table1' from 'db1.table1' to 'db1.newTable1'
    UniquePathsUpdate renameUpdate = new UniquePathsUpdate("u1",1, false);
    renameUpdate.newPathChange("db1.table1")
        .addToDelPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "table1"));
    renameUpdate.newPathChange("db1.newTable1")
        .addToAddPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable1"));
    sentryStore.renameAuthzPathsMapping("db1.table1", "db1.newTable1",
    "user/hive/warehouse/db1.db/table1", "user/hive/warehouse/db1.db/newTable1", renameUpdate);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(9, nodeMap.size());//Tree size
    assertEquals(2, pathsImage.size());
    assertEquals(3, sentryStore.getMPaths().size());
    assertTrue(pathsImage.containsKey("db1.newTable1"));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("user/hive/warehouse/db1.db/table1/p1",
            "user/hive/warehouse/db1.db/newTable1"),
            pathsImage.get("db1.newTable1")));

    // Query the persisted path change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPathChangeID();
    MSentryPathChange renamePathChange = sentryStore.getMSentryPathChangeByID(lastChangeID);
    assertEquals(renameUpdate.JSONSerialize(), renamePathChange.getPathChange());
    lastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(1, lastNotificationId.longValue());
    // Rename 'db1.table1' to "db1.table2" but did not change its location.
    renameUpdate = new UniquePathsUpdate("u2",2, false);
    renameUpdate.newPathChange("db1.newTable1")
        .addToDelPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable1"));
    renameUpdate.newPathChange("db1.newTable2")
        .addToAddPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable1"));
    sentryStore.renameAuthzObj("db1.newTable1", "db1.newTable2", renameUpdate);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(9, nodeMap.size());//Tree size
    assertEquals(2, pathsImage.size());
    assertEquals(3, sentryStore.getMPaths().size());
    assertTrue(pathsImage.containsKey("db1.newTable2"));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("user/hive/warehouse/db1.db/table1/p1",
            "user/hive/warehouse/db1.db/newTable1"),
            pathsImage.get("db1.newTable2")));
    lastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(2, lastNotificationId.longValue());

    // Query the persisted path change and ensure it equals to the original one
    lastChangeID = sentryStore.getLastProcessedPathChangeID();
    renamePathChange = sentryStore.getMSentryPathChangeByID(lastChangeID);
    assertEquals(renameUpdate.JSONSerialize(), renamePathChange.getPathChange());

    // Update path of 'db1.newTable2' from 'db1.newTable1' to 'db1.newTable2'
    UniquePathsUpdate update = new UniquePathsUpdate("u3",3, false);
    update.newPathChange("db1.newTable1")
        .addToDelPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable1"));
    update.newPathChange("db1.newTable1")
        .addToAddPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable2"));
    sentryStore.updateAuthzPathsMapping("db1.newTable2",
            "user/hive/warehouse/db1.db/newTable1",
            "user/hive/warehouse/db1.db/newTable2",
            update);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(9, nodeMap.size());//Tree size
    assertEquals(2, pathsImage.size());
    assertEquals(3, sentryStore.getMPaths().size());
    assertTrue(pathsImage.containsKey("db1.newTable2"));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("user/hive/warehouse/db1.db/table1/p1",
            "user/hive/warehouse/db1.db/newTable2"),
            pathsImage.get("db1.newTable2")));

    // Query the persisted path change and ensure it equals to the original one
    lastChangeID = sentryStore.getLastProcessedPathChangeID();
    MSentryPathChange updatePathChange = sentryStore.getMSentryPathChangeByID(lastChangeID);
    assertEquals(update.JSONSerialize(), updatePathChange.getPathChange());
    lastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(3, lastNotificationId.longValue());
  }

  @Test
  public void testPersistAndReplaceANewPathsImage() throws Exception {
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    long notificationID = 1;

    // First image to persist (this will be replaced later)
    authzPaths.put("db1.table1", Sets.newHashSet("/user/hive/warehouse/db2.db/table1.1",
        "/user/hive/warehouse/db2.db/table1.2"));
    authzPaths.put("db1.table2", Sets.newHashSet("/user/hive/warehouse/db2.db/table2.1",
        "/user/hive/warehouse/db2.db/table2.2"));
    sentryStore.persistFullPathsImage(authzPaths, notificationID);
    String[]prefixes = {"/user/hive/warehouse"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, true);

    assertEquals("/", root.getPathElement());
    assertEquals(9, nodeMap.size());//Tree size
    assertEquals(1, pathsUpdate.getImgNum());

    // Second image to persist (it should replace first image)
    authzPaths.clear();
    authzPaths.put("db3.table1", Sets.newHashSet("/another-warehouse/db2.db/table1.1",
        "/another-warehouse/db2.db/table1.2"));
    authzPaths.put("db3.table2", Sets.newHashSet("/another-warehouse/db2.db/table2.1",
        "/another-warehouse/db2.db/table2.2"));
    authzPaths.put("db4.table2", Sets.newHashSet("/another-warehouse/db2.db/table2.1",
        "/another-warehouse/db2.db/table2.3"));
    sentryStore.persistFullPathsImage(authzPaths, notificationID+1);

    prefixes = new String[]{"/another-warehouse"};
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, true);

    assertEquals("/", root.getPathElement());
    assertEquals(8, nodeMap.size());//Tree size
    assertEquals(2, pathsUpdate.getImgNum());
    assertEquals(3, pathImage.size());

    for (Map.Entry<String, Collection<String>> entry : pathImage.entrySet()) {
      assertEquals(2, entry.getValue().size());
    }

    assertEquals(2, pathImage.get("db4.table2").size());
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("/another-warehouse/db2.db/table1.1",
            "/another-warehouse/db2.db/table1.2"),
            pathImage.get("db3.table1")));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("/another-warehouse/db2.db/table2.1",
            "/another-warehouse/db2.db/table2.2"),
            pathImage.get("db3.table2")));

    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("/another-warehouse/db2.db/table2.1",
            "/another-warehouse/db2.db/table2.3"),
            pathImage.get("db4.table2")));

    assertEquals(6, sentryStore.getMPaths().size());
  }

  @Test
  public void testAddDeleteAfterReplacingANewPathsImage() throws Exception {
    long notificationID = 1;

    // Add some paths first (these should be replaced)
    UniquePathsUpdate addUpdate = new UniquePathsUpdate("u1", notificationID, false);
    addUpdate.newPathChange("db1.table").addToAddPaths(Arrays.asList("db1", "tbl1"));
    addUpdate.newPathChange("db1.table").addToAddPaths(Arrays.asList("db1", "tbl2"));
    sentryStore.addAuthzPathsMapping("db1.table", Sets.newHashSet("db1/tbl1", "db1/tbl2"), addUpdate);

    // Persist a new image that contains a new image ID (it replaces previous paths)
    notificationID ++;
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    authzPaths.put("db2.table3", Sets.newHashSet("/user/hive/warehouse/db2.db/table1.1",
        "/user/hive/warehouse/db2.db/table1.2"));
    sentryStore.persistFullPathsImage(authzPaths, notificationID);

    // Add new paths
    notificationID ++;
    UniquePathsUpdate newAddUpdate = new UniquePathsUpdate("u2", notificationID, false);
    newAddUpdate.newPathChange("db2.table").addToAddPaths(Arrays.asList("db2", "tbl1"));
    newAddUpdate.newPathChange("db2.table").addToAddPaths(Arrays.asList("db2", "tbl2"));
    sentryStore.addAuthzPathsMapping("db2.table", Sets.newHashSet("db2/tbl1", "db2/tbl2"), newAddUpdate);
    String[]prefixes = {"/"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(10, nodeMap.size());//Tree size
    assertEquals(2, pathImage.size());
    assertEquals(2, pathImage.get("db2.table").size());
    assertEquals(4, sentryStore.getMPaths().size());

    // Delete one path
    notificationID ++;
    UniquePathsUpdate delUpdate = new UniquePathsUpdate("u3", notificationID, false);
    delUpdate.newPathChange("db2.table").addToDelPaths(Arrays.asList("db2", "tbl1"));
    sentryStore.deleteAuthzPathsMapping("db2.table", Sets.newHashSet("db2/tbl1"), delUpdate);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(9, nodeMap.size());//Tree size
    assertEquals(2, pathImage.size());
    assertEquals(1, pathImage.get("db2.table").size());
    assertEquals(3, sentryStore.getMPaths().size());

    Long lastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(notificationID, lastNotificationId.longValue());
  }


  @Test
  public void testRenameUpdateAfterReplacingANewPathsImage() throws Exception {
    long notificationID = 1;

    Map<String, Collection<String>> authzPaths = new HashMap<>();
    // First image to persist (this will be replaced later)
    authzPaths.put("db1.table1", Sets.newHashSet("/user/hive/warehouse/db2.db/table1.1",
        "/user/hive/warehouse/db2.db/table1.2"));
    authzPaths.put("db1.table2", Sets.newHashSet("/user/hive/warehouse/db2.db/table2.1",
        "/user/hive/warehouse/db2.db/table2.2"));
    sentryStore.persistFullPathsImage(authzPaths, notificationID);

    // Second image to persist (it should replace first image)
    notificationID ++;
    authzPaths.clear();
    authzPaths.put("db3.table1", Sets.newHashSet("/another-warehouse/db3.db/table1.1",
        "/another-warehouse/db3.db/table1.2"));
    authzPaths.put("db3.table2", Sets.newHashSet("/another-warehouse/db3.db/table2.1",
        "/another-warehouse/db3.db/table2.2"));
    sentryStore.persistFullPathsImage(authzPaths, notificationID);

    // Rename path of 'db1.table1' from 'db1.table1' to 'db1.newTable1'
    notificationID ++;
    UniquePathsUpdate renameUpdate = new UniquePathsUpdate("u1", notificationID, false);
    renameUpdate.newPathChange("db3.table1")
        .addToDelPaths(Arrays.asList("another-warehouse", "db3.db", "table1.1"));
    renameUpdate.newPathChange("db1.newTable1")
        .addToAddPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable1"));
    sentryStore.renameAuthzPathsMapping("db3.table1", "db1.newTable1",
        "/another-warehouse/db3.db/table1.1", "user/hive/warehouse/db1.db/newTable1", renameUpdate);
    String[]prefixes = {"/"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, true);

    assertEquals("/", root.getPathElement());
    assertEquals(11, nodeMap.size());//Tree size
    assertEquals(2, pathsImage.size());
    assertEquals(4, sentryStore.getMPaths().size());
    assertTrue(pathsImage.containsKey("db1.newTable1"));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("/another-warehouse/db3.db/table1.2",
            "/user/hive/warehouse/db1.db/newTable1"),
            pathsImage.get("db1.newTable1")));

    // Update path of 'db1.newTable2' from 'db1.newTable1' to 'db1.newTable2'
    notificationID++;
    UniquePathsUpdate update = new UniquePathsUpdate("u2", notificationID, false);
    update.newPathChange("db1.newTable1")
        .addToDelPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable1"));
    update.newPathChange("db1.newTable1")
        .addToAddPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable2"));
    sentryStore.updateAuthzPathsMapping("db1.newTable2",
        "user/hive/warehouse/db1.db/newTable1",
        "user/hive/warehouse/db1.db/newTable2",
        update);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(12, nodeMap.size());//Tree size
    assertEquals(3, pathsImage.size());
    assertEquals(5, sentryStore.getMPaths().size());
    assertTrue(pathsImage.containsKey("db1.newTable2"));
    assertEquals(Lists.newArrayList("user/hive/warehouse/db1.db/newTable2"),
        pathsImage.get("db1.newTable2"));
  }

  @Test
  public void testQueryParamBuilder() {
    QueryParamBuilder paramBuilder;
    paramBuilder = newQueryParamBuilder();
    // Try single parameter
    paramBuilder.add("key", "val");
    assertEquals("(this.key == :key)", paramBuilder.toString());
    // Try adding second parameter plus add trimming and conversion
    // to lower case
    paramBuilder.add("key1", " Val1 ", true);
    assertEquals("(this.key == :key && this.key1 == :key1)",
            paramBuilder.toString());
    Map<String, Object> params = paramBuilder.getArguments();
    assertEquals("val", params.get("key"));
    assertEquals("Val1", params.get("key1"));

    paramBuilder = newQueryParamBuilder(QueryParamBuilder.Op.OR);
    paramBuilder.add("key", " Val ", true);
    paramBuilder.addNotNull("notNullField");
    paramBuilder.addNull("nullField");
    assertEquals("(this.key == :key || this.notNullField != \"__NULL__\" || this.nullField == \"__NULL__\")",
            paramBuilder.toString());
    params = paramBuilder.getArguments();
    assertEquals("Val", params.get("key"));

    paramBuilder = newQueryParamBuilder()
            .addNull("var1")
            .addNotNull("var2");
    assertEquals("(this.var1 == \"__NULL__\" && this.var2 != \"__NULL__\")",
            paramBuilder.toString());

    // Test newChild()
    paramBuilder = newQueryParamBuilder();
    paramBuilder
            .addString("e1")
            .addString("e2")
            .newChild()
            .add("v3", "e3")
            .add("v4", "e4")
            .newChild()
            .addString("e5")
            .addString("e6")
    ;
    assertEquals("(e1 && e2 && (this.v3 == :v3 || this.v4 == :v4 || (e5 && e6)))",
            paramBuilder.toString());


    paramBuilder = newQueryParamBuilder();
    paramBuilder
            .addString("e1")
            .addString("e2")
            .newChild()
            .add("v3", "e3")
            .add("v4", "e4")
            .newChild()
            .addString("e5")
            .addString("e6")
    ;

    params = paramBuilder.getArguments();
    assertEquals("e3", params.get("v3"));
    assertEquals("e4", params.get("v4"));

    // Test addSet
    paramBuilder = newQueryParamBuilder();
    Set<String>names = new HashSet<>();
    names.add("foo");
    names.add("bar");
    names.add("bob");

    paramBuilder.addSet("prefix == ", names, true);
    assertEquals("(prefix == :var0 && prefix == :var1 && prefix == :var2)",
            paramBuilder.toString());
    params = paramBuilder.getArguments();

    Set<String>result = new HashSet<>();
    result.add((String)params.get("var0"));
    result.add((String)params.get("var1"));
    result.add((String)params.get("var2"));
    assertTrue(result.containsAll(names));
    assertTrue(names.containsAll(result));
  }

  @Test
  public void testPrivilegesWithPermUpdate() throws Exception {
    String roleName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    String authzObj = "db1.tbl1";
    createRole(roleName);

    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("Column");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.SELECT);
    privilege.setCreateTime(System.currentTimeMillis());

    // Generate the permission add update authzObj "db1.tbl1"
    PermissionsUpdate addUpdate = new PermissionsUpdate(0, false);
    addUpdate.addPrivilegeUpdate(authzObj).putToAddPrivileges(
        new TPrivilegePrincipal(TPrivilegePrincipalType.ROLE, roleName), privilege.getAction().toUpperCase());

    // Grant the privilege to role test-privilege and verify it has been persisted.
    Map<TSentryPrivilege, Updateable.Update> addPrivilegesUpdateMap = Maps.newHashMap();
    addPrivilegesUpdateMap.put(privilege, addUpdate);
    sentryStore.alterSentryRoleGrantPrivileges(roleName, Sets.newHashSet(privilege), addPrivilegesUpdateMap);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    // Query the persisted perm change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPermChangeID();
    long initialID = lastChangeID;
    MSentryPermChange addPermChange = sentryStore.getMSentryPermChangeByID(lastChangeID);
    assertEquals(addUpdate.JSONSerialize(), addPermChange.getPermChange());

    // Generate the permission delete update authzObj "db1.tbl1"
    PermissionsUpdate delUpdate = new PermissionsUpdate(0, false);
    delUpdate.addPrivilegeUpdate(authzObj).putToDelPrivileges(
            new TPrivilegePrincipal(TPrivilegePrincipalType.ROLE, roleName),
            privilege.getAction().toUpperCase());

    // Revoke the same privilege and verify it has been removed.
    Map<TSentryPrivilege, Updateable.Update> delPrivilegesUpdateMap = Maps.newHashMap();
    delPrivilegesUpdateMap.put(privilege, delUpdate);
    sentryStore.alterSentryRoleRevokePrivileges(roleName,
        Sets.newHashSet(privilege), delPrivilegesUpdateMap);
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(0, privileges.size());

    // Query the persisted perm change and ensure it equals to the original one
    lastChangeID = sentryStore.getLastProcessedPermChangeID();
    MSentryPermChange delPermChange = sentryStore.getMSentryPermChangeByID(lastChangeID);
    assertEquals(delUpdate.JSONSerialize(), delPermChange.getPermChange());

    // Verify getMSentryPermChanges will return all MSentryPermChanges up
    // to the given changeID.
    List<MSentryPermChange> mSentryPermChanges = sentryStore.getMSentryPermChanges(initialID);
    assertEquals(lastChangeID - initialID + 1, mSentryPermChanges.size());

    // Verify ifPermChangeExists will return true for persisted MSentryPermChange.
    assertEquals(true, sentryStore.permChangeExists(1));
  }

  @Test
  public void testAddDeleteGroupsWithPermUpdate() throws Exception {
    String roleName = "test-groups";
    String grantor = "g1";
    createRole(roleName);

    Set<TSentryGroup> groups = Sets.newHashSet();
    TSentryGroup group = new TSentryGroup();
    group.setGroupName("test-groups-g1");
    groups.add(group);
    group = new TSentryGroup();
    group.setGroupName("test-groups-g2");
    groups.add(group);

    // Generate the permission add update for role "test-groups"
    PermissionsUpdate addUpdate = new PermissionsUpdate(0, false);
    TRoleChanges addrUpdate = addUpdate.addRoleUpdate(roleName);
    for (TSentryGroup g : groups) {
      addrUpdate.addToAddGroups(g.getGroupName());
    }

    // Assign the role "test-groups" to the groups and verify.
    sentryStore.alterSentryRoleAddGroups(grantor, roleName, groups, addUpdate);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    assertEquals(2, role.getGroups().size());

    // Query the persisted perm change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPermChangeID();
    MSentryPermChange addPermChange = sentryStore.getMSentryPermChangeByID(lastChangeID);
    assertEquals(addUpdate.JSONSerialize(), addPermChange.getPermChange());

    // Generate the permission add update for role "test-groups"
    PermissionsUpdate delUpdate = new PermissionsUpdate(0, false);
    TRoleChanges delrUpdate = delUpdate.addRoleUpdate(roleName);
    for (TSentryGroup g : groups) {
      delrUpdate.addToDelGroups(g.getGroupName());
    }

    // Revoke the role "test-groups" to the groups and verify.
    sentryStore.alterSentryRoleDeleteGroups(roleName, groups, delUpdate);
    role = sentryStore.getMSentryRoleByName(roleName);
    assertEquals(Collections.emptySet(), role.getGroups());

    // Query the persisted perm change and ensure it equals to the original one
    MSentryPermChange delPermChange = sentryStore.getMSentryPermChangeByID(lastChangeID + 1);
    assertEquals(delUpdate.JSONSerialize(), delPermChange.getPermChange());
  }

  @Test
  public void testCreateDropRoleWithPermUpdate() throws Exception {
    String roleName = "test-drop-role";
    createRole(roleName);

    // Generate the permission del update for dropping role "test-drop-role"
    PermissionsUpdate delUpdate = new PermissionsUpdate(0, false);
    delUpdate.addPrivilegeUpdate(PermissionsUpdate.ALL_AUTHZ_OBJ).putToDelPrivileges(
            new TPrivilegePrincipal(TPrivilegePrincipalType.ROLE, roleName),
            PermissionsUpdate.ALL_AUTHZ_OBJ);
    delUpdate.addRoleUpdate(roleName).addToDelGroups(PermissionsUpdate.ALL_GROUPS);

    // Drop the role and verify.
    sentryStore.dropSentryRole(roleName, delUpdate);
    checkRoleDoesNotExist(roleName);

    // Query the persisted perm change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPermChangeID();
    MSentryPermChange delPermChange = sentryStore.getMSentryPermChangeByID(lastChangeID);
    assertEquals(delUpdate.JSONSerialize(), delPermChange.getPermChange());
  }

  @Test
  public void testDropObjWithPermUpdate() throws Exception {
    String roleName1 = "list-privs-r1", roleName2 = "list-privs-r2";
    sentryStore.createSentryRole(roleName1);
    sentryStore.createSentryRole(roleName2);

    String authzObj = "db1.tbl1";
    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName("tbl1");
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction("SELECT");

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1), null);

    // Generate the permission drop update for dropping privilege for "db1.tbl1"
    PermissionsUpdate dropUpdate = new PermissionsUpdate(0, false);
    dropUpdate.addPrivilegeUpdate(authzObj).putToDelPrivileges(new TPrivilegePrincipal(TPrivilegePrincipalType.ROLE,
            PermissionsUpdate.ALL_ROLES),
            PermissionsUpdate.ALL_ROLES);

    // Drop the privilege and verify.
    sentryStore.dropPrivilege(toTSentryAuthorizable(privilege_tbl1), dropUpdate);
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName1).size());
    assertEquals(0, sentryStore.getAllTSentryPrivilegesByRoleName(roleName2).size());

    // Query the persisted perm change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPermChangeID();
    MSentryPermChange dropPermChange = sentryStore.getMSentryPermChangeByID(lastChangeID);
    assertEquals(dropUpdate.JSONSerialize(), dropPermChange.getPermChange());
  }

  @Test
  public void testRenameObjWithPermUpdate() throws Exception {
    String roleName1 = "role1";
    String table1 = "tbl1", table2 = "tbl2";

    sentryStore.createSentryRole(roleName1);

    TSentryPrivilege privilege_tbl1 = new TSentryPrivilege();
    privilege_tbl1.setPrivilegeScope("TABLE");
    privilege_tbl1.setServerName("server1");
    privilege_tbl1.setDbName("db1");
    privilege_tbl1.setTableName(table1);
    privilege_tbl1.setCreateTime(System.currentTimeMillis());
    privilege_tbl1.setAction(AccessConstants.ALL);

    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName1, Sets.newHashSet(privilege_tbl1), null);

    // Generate the permission rename update for renaming privilege for "db1.tbl1"
    String oldAuthz = "db1.tbl1";
    String newAuthz = "db1.tbl2";
    PermissionsUpdate renameUpdate = new PermissionsUpdate(0, false);
    TPrivilegeChanges privUpdate = renameUpdate.addPrivilegeUpdate(PermissionsUpdate.RENAME_PRIVS);
    privUpdate.putToAddPrivileges(new TPrivilegePrincipal(TPrivilegePrincipalType.AUTHZ_OBJ, newAuthz), newAuthz);
    privUpdate.putToDelPrivileges(new TPrivilegePrincipal(TPrivilegePrincipalType.AUTHZ_OBJ, oldAuthz), oldAuthz);

    // Rename the privilege and verify.
    TSentryAuthorizable oldTable = toTSentryAuthorizable(privilege_tbl1);
    TSentryAuthorizable newTable = toTSentryAuthorizable(privilege_tbl1);
    newTable.setTable(table2);
    sentryStore.renamePrivilege(oldTable, newTable, renameUpdate);

    Set<TSentryPrivilege> privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName1);
    assertEquals(1, privilegeSet.size());
    for (TSentryPrivilege privilege : privilegeSet) {
      assertTrue(table2.equalsIgnoreCase(privilege.getTableName()));
    }

    // Query the persisted perm change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPermChangeID();
    MSentryPermChange renamePermChange = sentryStore.getMSentryPermChangeByID(lastChangeID);
    assertEquals(renameUpdate.JSONSerialize(), renamePermChange.getPermChange());
  }

  protected static void addGroupsToUser(String user, String... groupNames) {
    policyFile.addGroupsToUser(user, groupNames);
  }

  protected static void writePolicyFile() throws Exception {
    policyFile.write(policyFilePath);
  }

  @Test
  public void testPurgeDeltaChanges() throws Exception {
    String role = "purgeRole";
    String table = "purgeTable";

    assertEquals(0, sentryStore.getMSentryPermChanges().size());
    assertEquals(0, sentryStore.getMSentryPathChanges().size());

    sentryStore.createSentryRole(role);
    int privCleanCount = ServerConfig.SENTRY_DELTA_KEEP_COUNT_DEFAULT;
    int extraPrivs = 5;

    final int numPermChanges = extraPrivs + privCleanCount;
    for (int i = 0; i < numPermChanges; i++) {
      TSentryPrivilege privilege = new TSentryPrivilege();
      privilege.setPrivilegeScope("Column");
      privilege.setServerName("server");
      privilege.setDbName("db");
      privilege.setTableName(table);
      privilege.setColumnName("column");
      privilege.setAction(AccessConstants.SELECT);
      privilege.setCreateTime(System.currentTimeMillis());

      PermissionsUpdate update = new PermissionsUpdate(i + 1, false);
      sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, role, Sets.newHashSet(privilege), Lists.newArrayList(update));
    }
    assertEquals(numPermChanges, sentryStore.getMSentryPermChanges().size());

    sentryStore.purgeDeltaChangeTables();
    assertEquals(privCleanCount, sentryStore.getMSentryPermChanges().size());

    // TODO: verify MSentryPathChange being purged.
    // assertEquals(1, sentryStore.getMSentryPathChanges().size());
  }

  @Test
  public void testpurgeNotificationIdTable() throws Exception {

    int totalentires = 200;
    int remainingEntires = ServerConfig.SENTRY_HMS_NOTIFICATION_ID_KEEP_COUNT_DEFAULT;
    assertTrue(sentryStore.isHmsNotificationEmpty());
    for(int id = 1; id <= totalentires; id++) {
      sentryStore.persistLastProcessedNotificationID((long)id);
    }
    assertEquals(totalentires, sentryStore.getMSentryHmsNotificationCore().size());
    sentryStore.purgeNotificationIdTable();

    // Make sure that sentry store still hold entries based on SENTRY_HMS_NOTIFICATION_ID_KEEP_COUNT_DEFAULT
    assertEquals(remainingEntires, sentryStore.getMSentryHmsNotificationCore().size());

    sentryStore.purgeNotificationIdTable();
    // Make sure that sentry store still hold entries based on SENTRY_HMS_NOTIFICATION_ID_KEEP_COUNT_DEFAULT
    assertEquals(remainingEntires, sentryStore.getMSentryHmsNotificationCore().size());

    sentryStore.clearAllTables();


    totalentires = 50;
    for(int id = 1; id <= totalentires; id++) {
      sentryStore.persistLastProcessedNotificationID((long)id);
    }
    assertEquals(totalentires, sentryStore.getMSentryHmsNotificationCore().size());
    sentryStore.purgeNotificationIdTable();

    // Make sure that sentry store still holds all the entries as total entries is less than
    // SENTRY_HMS_NOTIFICATION_ID_KEEP_COUNT_DEFAULT.
    assertEquals(totalentires, sentryStore.getMSentryHmsNotificationCore().size());
  }


  /**
   * This test verifies that in the case of concurrently updating delta change tables, no gap
   * between change ID was made. All the change IDs must be consecutive ({@see SENTRY-1643}).
   *
   * @throws Exception
   */
  @Test(timeout = 60000)
  public void testConcurrentUpdateChanges() throws Exception {
    final int numThreads = 20;
    final int numChangesPerThread = 100;
    final TransactionManager tm = sentryStore.getTransactionManager();
    final AtomicLong seqNumGenerator = new AtomicLong(0);
    final CyclicBarrier barrier = new CyclicBarrier(numThreads);

    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
    for (int i = 0; i < numThreads; i++) {
      executor.submit(new Runnable() {
        @Override
        public void run() {
          try {
            barrier.await();
          } catch (Exception e) {
            LOGGER.error("Barrier failed to await", e);
            return;
          }
          for (int j = 0; j < numChangesPerThread; j++) {
            List<TransactionBlock<Object>> tbs = new ArrayList<>();
            PermissionsUpdate update =
                new PermissionsUpdate(seqNumGenerator.getAndIncrement(), false);
            tbs.add(new DeltaTransactionBlock(update));
            try {
              tm.executeTransactionBlocksWithRetry(tbs);
            } catch (Exception e) {
              LOGGER.error("Failed to execute permission update transaction", e);
              fail(String.format("Transaction failed: %s", e.getMessage()));
            }
          }
        }
      });
    }
    executor.shutdown();
    executor.awaitTermination(60, TimeUnit.SECONDS);

    List<MSentryPermChange> changes = sentryStore.getMSentryPermChanges();
    int actualSize = changes.size();
    if (actualSize != (numThreads * numChangesPerThread)) {
      LOGGER.warn("Detected {} dropped changes", ((numChangesPerThread * numThreads) - actualSize));
    }
    TreeSet<Long> changeIDs = new TreeSet<>();
    for (MSentryPermChange change : changes) {
      changeIDs.add(change.getChangeID());
    }
    assertEquals("duplicated change ID", actualSize, changeIDs.size());

    long prevId = changeIDs.first() - 1;
    for (Long changeId : changeIDs) {
      assertTrue(String.format("Found non-consecutive number: prev=%d cur=%d", prevId, changeId),
          changeId - prevId == 1);
      prevId = changeId;
    }
  }

  @Test
  public void testDuplicateNotification() throws Exception {
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    Long lastNotificationId = sentryStore.getLastProcessedNotificationID();

    lastNotificationId ++;
    authzPaths.put("db1.table1", Sets.newHashSet("user/hive/warehouse/db1.db/table1",
      "user/hive/warehouse/db1.db/table1/p1"));
    authzPaths.put("db1.table2", Sets.newHashSet("user/hive/warehouse/db1.db/table2"));
    sentryStore.persistFullPathsImage(authzPaths, lastNotificationId);
    String[]prefixes = {"/user/hive/warehouse"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(8, nodeMap.size());//Tree size
    assertEquals(2, pathsImage.size());

    if (lastNotificationId == null) {
      lastNotificationId = SentryConstants.EMPTY_NOTIFICATION_ID;
    }

    // Rename path of 'db1.table1' from 'db1.table1' to 'db1.newTable1'
    lastNotificationId ++;
    UniquePathsUpdate renameUpdate = new UniquePathsUpdate("u1", lastNotificationId, false);
    renameUpdate.newPathChange("db1.table1")
      .addToDelPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "table1"));
    renameUpdate.newPathChange("db1.newTable1")
      .addToAddPaths(Arrays.asList("user", "hive", "warehouse", "db1.db", "newTable1"));
    sentryStore.renameAuthzPathsMapping("db1.table1", "db1.newTable1",
      "user/hive/warehouse/db1.db/table1", "user/hive/warehouse/db1.db/newTable1", renameUpdate);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathsImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathsImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(9, nodeMap.size());//Tree size
    assertEquals(2, pathsImage.size());
    assertEquals(3, sentryStore.getMPaths().size());
    assertTrue(pathsImage.containsKey("db1.newTable1"));
    assertTrue(CollectionUtils.isEqualCollection(Lists.newArrayList("user/hive/warehouse/db1.db/table1/p1",
            "user/hive/warehouse/db1.db/newTable1"),
            pathsImage.get("db1.newTable1")));

    // Query the persisted path change and ensure it equals to the original one
    long lastChangeID = sentryStore.getLastProcessedPathChangeID();
    MSentryPathChange renamePathChange = sentryStore.getMSentryPathChangeByID(lastChangeID);
    assertEquals(renameUpdate.JSONSerialize(), renamePathChange.getPathChange());
    Long savedLastNotificationId = sentryStore.getLastProcessedNotificationID();
    assertEquals(lastNotificationId.longValue(), savedLastNotificationId.longValue());


    // Process the notificaiton second time
    try {
      sentryStore.renameAuthzPathsMapping("db1.table1", "db1.newTable1",
        "user/hive/warehouse/db1.db/table1", "user/hive/warehouse/db1.db/newTable1", renameUpdate);
    } catch (Exception e) {
      if (!(e.getCause() instanceof JDODataStoreException)) {
        fail("Unexpected failure occured while processing duplicate notification");
      }
    }
  }

  @Test
  public void testIsAuthzPathsMappingEmpty() throws Exception {
    // Add "db1.table1" authzObj
    UniquePathsUpdate addUpdate = new UniquePathsUpdate("u1",1, false);
    addUpdate.newPathChange("db1.table").
      addToAddPaths(Arrays.asList("db1", "tbl1"));
    addUpdate.newPathChange("db1.table").
      addToAddPaths(Arrays.asList("db1", "tbl2"));

    // Persist an empty image so that we can add paths to it.
    sentryStore.persistFullPathsImage(new HashMap<String, Collection<String>>(), 0);

    assertEquals(sentryStore.isAuthzPathsMappingEmpty(), true);
    sentryStore.addAuthzPathsMapping("db1.table",
      Sets.newHashSet("db1/tbl1", "db1/tbl2"), addUpdate);
    String[]prefixes = {"/"};
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(4, nodeMap.size());//Tree size
    assertEquals(1, pathImage.size());
    assertEquals(2, pathImage.get("db1.table").size());
    assertEquals(2, sentryStore.getMPaths().size());
    assertEquals(sentryStore.isAuthzPathsMappingEmpty(), false);
    sentryStore.clearAllTables();
    assertEquals(sentryStore.isAuthzPathsMappingEmpty(), true);
  }

  @Test
  public void testAddDeleteAuthzPathsMappingNoDeltaSavedWithoutHDFSSync() throws Exception {

    // disable HDFS
    conf.set(ServiceConstants.ServerConfig.PROCESSOR_FACTORIES, "");
    conf.set(ServiceConstants.ServerConfig.SENTRY_POLICY_STORE_PLUGINS, "");
    SentryStore localSentryStore = new SentryStore(conf);

    // Persist an empty image so that we can add paths to it.
    localSentryStore.persistFullPathsImage(new HashMap<String, Collection<String>>(), 0);

    // Add "db1.table1" authzObj
    Long lastNotificationId = sentryStore.getLastProcessedNotificationID();
    UniquePathsUpdate addUpdate = new UniquePathsUpdate("u1",1, false);
    addUpdate.newPathChange("db1.table").
        addToAddPaths(Arrays.asList("db1", "tbl1"));
    addUpdate.newPathChange("db1.table").
        addToAddPaths(Arrays.asList("db1", "tbl2"));

    localSentryStore.addAuthzPathsMapping("db1.table",
        Sets.newHashSet("db1/tbl1", "db1/tbl2"), addUpdate);
    String[]prefixes = {"/"};
    PathsUpdate pathsUpdate = localSentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsDump pathsDump = pathsUpdate.toThrift().getPathsDump();
    Map<Integer, TPathEntry>nodeMap = pathsDump.getNodeMap();
    TPathEntry root = nodeMap.get(pathsDump.getRootId());
    Map<String, Collection<String>> pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(4, nodeMap.size());//Tree size
    assertEquals(1, pathImage.size());
    assertEquals(2, pathImage.get("db1.table").size());
    assertEquals(2, localSentryStore.getMPaths().size());

    // Query the persisted path change and ensure it is not saved
    long lastChangeID = localSentryStore.getLastProcessedPathChangeID();
    assertEquals(0, lastChangeID);

    // Delete path 'db1.db/tbl1' from "db1.table1" authzObj.
    UniquePathsUpdate delUpdate = new UniquePathsUpdate("u2",2, false);
    delUpdate.newPathChange("db1.table")
        .addToDelPaths(Arrays.asList("db1", "tbl1"));
    localSentryStore.deleteAuthzPathsMapping("db1.table", Sets.newHashSet("db1/tbl1"), delUpdate);
    pathsUpdate = localSentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(3, nodeMap.size());//Tree size
    assertEquals(1, pathImage.size());
    assertEquals(1, pathImage.get("db1.table").size());
    assertEquals(1, localSentryStore.getMPaths().size());

    // Query the persisted path change and ensure it is not saved
    lastChangeID = localSentryStore.getLastProcessedPathChangeID();
    assertEquals(0, lastChangeID);

    // Delete "db1.table" authzObj from the authzObj -> [Paths] mapping.
    UniquePathsUpdate delAllupdate = new UniquePathsUpdate("u3",3, false);
    delAllupdate.newPathChange("db1.table")
        .addToDelPaths(Lists.newArrayList(PathsUpdate.ALL_PATHS));
    localSentryStore.deleteAllAuthzPathsMapping("db1.table", delAllupdate);
    pathsUpdate = localSentryStore.retrieveFullPathsImageUpdate(prefixes);
    pathsDump = pathsUpdate.toThrift().getPathsDump();
    nodeMap = pathsDump.getNodeMap();
    root = nodeMap.get(pathsDump.getRootId());
    pathImage = new HashMap<>();
    buildPathsImageMap(nodeMap, root, "", pathImage, false);

    assertEquals("/", root.getPathElement());
    assertEquals(1, nodeMap.size());//Tree size
    assertEquals(0, pathImage.size());
    assertEquals(0, localSentryStore.getMPaths().size());

    // Query the persisted path change and ensure it is not saved
    lastChangeID = localSentryStore.getLastProcessedPathChangeID();
    assertEquals(0, lastChangeID);

    lastNotificationId = localSentryStore.getLastProcessedNotificationID();
    assertEquals(0, lastNotificationId.longValue());

    // enable HDFS for other tests
    conf.set(ServiceConstants.ServerConfig.PROCESSOR_FACTORIES, "org.apache.sentry.hdfs.SentryHDFSServiceProcessorFactory");
    conf.set(ServiceConstants.ServerConfig.SENTRY_POLICY_STORE_PLUGINS, "org.apache.sentry.hdfs.SentryPlugin");
  }

  /**
   * Test retrieveFullPathsImageUpdate() when no image is present.
   * @throws Exception
   */
  @Test
  public void testRetrieveEmptyPathImage() throws Exception {
    String[] prefixes = {};

    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    TPathsUpdate tPathsUpdate = pathsUpdate.toThrift();
    TPathsDump pathDump = tPathsUpdate.getPathsDump();
    Map<Integer, TPathEntry> nodeMap = pathDump.getNodeMap();
    assertEquals(1, nodeMap.size());
    System.out.printf(nodeMap.toString());
  }

  /**
   * Test retrieveFullPathsImageUpdate() when a single path is present.
   * @throws Exception
   */
  @Test
  public void testRetrievePathImageWithSingleEntry() throws Exception {
    String prefix = "user/hive/warehouse";
    String[] prefixes = {"/" + prefix};
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    // Makes sure that authorizable object could be associated
    // with different paths and can be properly persisted into database.
    String tablePath = prefix + "/db2.db/table1.1";
    authzPaths.put("db1.table1", Sets.newHashSet(tablePath));
    long notificationID = 1;
    sentryStore.persistFullPathsImage(authzPaths, notificationID);

    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    assertEquals(notificationID, pathsUpdate.getImgNum());
    TPathsUpdate tPathsUpdate = pathsUpdate.toThrift();
    TPathsDump pathDump = tPathsUpdate.getPathsDump();
    Map<Integer, TPathEntry> nodeMap = pathDump.getNodeMap();
    System.out.printf(nodeMap.toString());
    assertEquals(6, nodeMap.size());
    int rootId = pathDump.getRootId();
    TPathEntry root = nodeMap.get(rootId);
    assertEquals("/", root.getPathElement());
    List<Integer> children;
    TPathEntry child = root;

    // Walk tree down and verify elements
    for (String path: tablePath.split("/")) {
      children = child.getChildren();
      assertEquals(1, children.size());
      child = nodeMap.get(children.get(0));
      assertEquals(path, child.getPathElement());
    }
  }

  /**
   * Test paths with multiple leading slashes
   * @throws Exception
   */
  @Test
  public void testRetrievePathImageWithMultipleLeadingSlashes() throws Exception {
    //Test with no leading slashes
    String prefix = "user/hive/warehouse";
    String []prefixes = {"/" + prefix};
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    // Makes sure that authorizable object could be associated
    // with different paths and can be properly persisted into database.
    String tablePath = prefix + "/loc1/db2.db/table1.1";
    authzPaths.put("db1.table1", Sets.newHashSet(tablePath));
    long notificationID = 1;
    sentryStore.persistFullPathsImage(authzPaths, notificationID);
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    assertEquals(notificationID, pathsUpdate.getImgNum());
    TPathsUpdate tPathsUpdate = pathsUpdate.toThrift();
    TPathsDump pathDump = tPathsUpdate.getPathsDump();
    Map<Integer, TPathEntry> nodeMap = pathDump.getNodeMap();
    assertEquals(7, nodeMap.size());

    //Test with single leading slashes
    prefix = "/user/hive/warehouse";
    prefixes = new String[]{prefix};
    authzPaths = new HashMap<>();
    // Makes sure that authorizable object could be associated
    // with different paths and can be properly persisted into database.
    tablePath = prefix + "/loc1/db2.db/table1.1";
    authzPaths.put("db1.table1", Sets.newHashSet(tablePath));
    notificationID = 2;
    sentryStore.persistFullPathsImage(authzPaths, notificationID);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    assertEquals(notificationID, pathsUpdate.getImgNum());
    tPathsUpdate = pathsUpdate.toThrift();
    pathDump = tPathsUpdate.getPathsDump();
    nodeMap = pathDump.getNodeMap();
    assertEquals(7, nodeMap.size());

    //Test with multiple leading slash
    prefix = "///user/hive/warehouse";
    prefixes = new String[]{prefix};
    authzPaths = new HashMap<>();
    // Makes sure that authorizable object could be associated
    // with different paths and can be properly persisted into database.
    tablePath = prefix + "/loc1/db2.db/table1.1";
    authzPaths.put("db1.table1", Sets.newHashSet(tablePath));
    notificationID = 3;
    sentryStore.persistFullPathsImage(authzPaths, notificationID);
    pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    assertEquals(notificationID, pathsUpdate.getImgNum());
    tPathsUpdate = pathsUpdate.toThrift();
    pathDump = tPathsUpdate.getPathsDump();
    nodeMap = pathDump.getNodeMap();
    assertEquals(7, nodeMap.size());
  }

  /**
   * Create a user with the given name and verify that it is created
   *
   * @param userName
   * @throws Exception
   */
  private void createUser(String userName) throws Exception {
    checkUserDoesNotExist(userName);
    sentryStore.createSentryUser(userName);
    checkUserExists(userName);
  }

  /**
   * Fail test if user already exists
   * @param userName User name to checl
   * @throws Exception
   */
  private void checkUserDoesNotExist(String userName) throws Exception {
    try {
      sentryStore.getMSentryUserByName(userName);
      fail("User " + userName + "already exists");
    } catch (SentryNoSuchObjectException e) {
      // Ok
    }
  }

  /**
   * Fail test if user doesn't exist
   * @param userName User name to checl
   * @throws Exception
   */
  private void checkUserExists(String userName) throws Exception {
    assertEquals(userName.toLowerCase(),
        sentryStore.getMSentryUserByName(userName).getUserName());
  }

  @Test
  public void testGrantRevokePrivilegeForUser() throws Exception {
    String userName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    createUser(userName);
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);
    MSentryUser user = sentryStore.getMSentryUserByName(userName);
    Set<MSentryPrivilege> privileges = user.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());
    privilege.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking SELECT, we should have (INSERT)
    user = sentryStore.getMSentryUserByName(userName);
    privileges = user.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());
    for (MSentryPrivilege mPrivilege : privileges) {
      assertEquals(server, mPrivilege.getServerName());
      assertEquals(db, mPrivilege.getDbName());
      assertEquals(table, mPrivilege.getTableName());
      assertNotSame(AccessConstants.SELECT, mPrivilege.getAction());
      assertFalse(mPrivilege.getGrantOption());
    }
    long numDBPrivs = sentryStore.countMSentryPrivileges();
    assertEquals("Privilege count", numDBPrivs,1);

    privilege.setAction(AccessConstants.INSERT);

    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);
    user = sentryStore.getMSentryUserByName(userName, false);
    assertNull(user);
  }

  /**
   * Test after granting DB ALL privilege, can still grant table ALL privilege
   * @throws Exception
   */
  @Test
  public void testGrantDuplicatePrivilegeHierchy() throws Exception {
    // grant database all privilege
    String roleName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    createRole(roleName);
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("DATABASE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    // grant table all privlege
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server.toUpperCase());
    privilege.setDbName(db.toUpperCase());
    privilege.setTableName(table.toUpperCase());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);

    // check if the table privilege is created
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 2, privileges.size());
  }

  @Test
  public void testListSentryPrivilegesForUsersAndGroups() throws Exception {
    String roleName = "role1";
    String groupName = "list-privs-g1";
    String userName = "u1";
    String grantor = "g1";
    sentryStore.createSentryRole(roleName);

    TSentryPrivilege privilege1 = new TSentryPrivilege();
    privilege1.setPrivilegeScope("TABLE");
    privilege1.setServerName("server1");
    privilege1.setDbName("db1");
    privilege1.setTableName("tbl1");
    privilege1.setAction("SELECT");
    privilege1.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege1), null);

    TSentryPrivilege privilege2 = new TSentryPrivilege();
    privilege2.setPrivilegeScope("SERVER");
    privilege2.setServerName("server1");
    privilege2.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege2), null);

    Set<TSentryGroup> groups = Sets.newHashSet();
    TSentryGroup group = new TSentryGroup();
    group.setGroupName(groupName);
    groups.add(group);
    sentryStore.alterSentryRoleAddGroups(grantor, roleName, groups);

    // list-privs-g1 has privilege1
    // u1 has privilege2
    Set<TSentryPrivilege> expectedPrivs = new HashSet<>();
    expectedPrivs.add(privilege1);
    expectedPrivs.add(privilege2);

    assertEquals(expectedPrivs,
                 sentryStore.listSentryPrivilegesByUsersAndGroups(
                     Sets.newHashSet(groupName),
                     Sets.newHashSet(userName),
                     new TSentryActiveRoleSet(true, new HashSet<>()),
                     null));
  }

  @Test
  public void testListSentryPrivilegesForProviderForUser() throws Exception {
    String userName1 = "list-privs-user1";
    String userName2 = "list-privs-user2";
    sentryStore.createSentryUser(userName1);
    sentryStore.createSentryUser(userName2);

    TSentryPrivilege privilege1 = new TSentryPrivilege();
    privilege1.setPrivilegeScope("TABLE");
    privilege1.setServerName("server1");
    privilege1.setDbName("db1");
    privilege1.setTableName("tbl1");
    privilege1.setAction("SELECT");
    privilege1.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName1, Sets.newHashSet(privilege1), null);

    privilege1.setAction("ALL");
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName2, Sets.newHashSet(privilege1), null);

    assertEquals(Sets.newHashSet("server=server1->db=db1->table=tbl1->action=select"),
        SentryStore.toTrimedLower(sentryStore.listAllSentryPrivilegesForProvider(
            new HashSet<String>(),
            Sets.newHashSet(userName1),
            new TSentryActiveRoleSet(true, new HashSet<String>()))));
  }

  @Test
  public void testListSentryPrivilegesByAuthorizableForUser() throws Exception {
    String userName1 = "list-privs-user1";
    sentryStore.createSentryUser(userName1);

    TSentryPrivilege privilege1 = new TSentryPrivilege();
    privilege1.setPrivilegeScope("TABLE");
    privilege1.setServerName("server1");
    privilege1.setDbName("db1");
    privilege1.setTableName("tbl1");
    privilege1.setAction("SELECT");
    privilege1.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName1, Sets.newHashSet(privilege1), null);

    TSentryAuthorizable tSentryAuthorizable = new TSentryAuthorizable();
    tSentryAuthorizable.setServer("server1");
    tSentryAuthorizable.setDb("db1");
    tSentryAuthorizable.setTable("tbl1");

    TSentryPrivilegeMap map = sentryStore.listSentryPrivilegesByAuthorizableForUser(
        Sets.newHashSet(userName1),
        tSentryAuthorizable,false);
    assertEquals(1, map.getPrivilegeMapSize());
    assertEquals(Sets.newHashSet(userName1), map.getPrivilegeMap().keySet());
  }

  @Test
  public void testGrantRevokePrivilegeMultipleTimesForRole() throws Exception {
    String roleName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    createRole(roleName);
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);

    MSentryRole role = sentryStore.getMSentryRoleByName(roleName);
    Set<MSentryPrivilege> privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    privilege.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking SELECT, we should have (INSERT)
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    // second round
    privilege.setAction(AccessConstants.ALL);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    List<MSentryPrivilege> totalPrivileges = sentryStore.getAllMSentryPrivileges();
    assertEquals(totalPrivileges.toString(),1, totalPrivileges.size());

    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    privilege.setAction(AccessConstants.INSERT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.ROLE, roleName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking INSERT, we should have (SELECT)
    totalPrivileges = sentryStore.getAllMSentryPrivileges();
    assertEquals(totalPrivileges.toString(),1, totalPrivileges.size());
    role = sentryStore.getMSentryRoleByName(roleName);
    privileges = role.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    sentryStore.dropSentryRole(roleName);
  }

  @Test
  public void testGrantRevokePrivilegeMultipleTimesForUser() throws Exception {
    String userName = "test-privilege";
    String server = "server1";
    String db = "db1";
    String table = "tbl1";
    createUser(userName);
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope("TABLE");
    privilege.setServerName(server);
    privilege.setDbName(db);
    privilege.setTableName(table);
    privilege.setAction(AccessConstants.ALL);
    privilege.setCreateTime(System.currentTimeMillis());
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);

    MSentryUser user = sentryStore.getMSentryUserByName(userName);
    Set<MSentryPrivilege> privileges = user.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    privilege.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking SELECT, we should have (INSERT)
    user = sentryStore.getMSentryUserByName(userName);
    privileges = user.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    // second round
    privilege.setAction(AccessConstants.ALL);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);
    List<MSentryPrivilege> totalPrivileges = sentryStore.getAllMSentryPrivileges();
    assertEquals(totalPrivileges.toString(),1, totalPrivileges.size());

    user = sentryStore.getMSentryUserByName(userName);
    privileges = user.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    privilege.setAction(AccessConstants.INSERT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking INSERT, we should have (SELECT)
    totalPrivileges = sentryStore.getAllMSentryPrivileges();
    assertEquals(totalPrivileges.toString(),1, totalPrivileges.size());

    user = sentryStore.getMSentryUserByName(userName);
    privileges = user.getPrivileges();
    assertEquals(privileges.toString(), 1, privileges.size());

    privilege.setAction(AccessConstants.SELECT);
    sentryStore.alterSentryRevokePrivileges(SentryPrincipalType.USER, userName, Sets.newHashSet(privilege), null);
    // after having ALL and revoking INSERT and SELECT, we should have NO privileges
    // user should be removed automatically
    user = sentryStore.getMSentryUserByName(userName, false);
    assertNull(user);
  }

  @Test
  public void testGetAllRolesPrivileges() throws Exception {
    Map<String, Set<TSentryPrivilege>> allPrivileges;

    // The map must be empty (no null) if no roles exist on the system yet
    allPrivileges = sentryStore.getAllRolesPrivileges();
    assertNotNull(allPrivileges);
    assertTrue(allPrivileges.isEmpty());

    final String ROLE1 = "role1";
    final TSentryPrivilege ROLE1_PRIV1 =
      toTSentryPrivilege("ALL", "TABLE", "server1", "db1", "table1");
    final TSentryPrivilege ROLE1_PRIV2 =
      toTSentryPrivilege("SELECT", "TABLE", "server1", "db1", "table2");

    createRole(ROLE1);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, ROLE1, Sets.newHashSet(ROLE1_PRIV1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, ROLE1, Sets.newHashSet(ROLE1_PRIV2), null);

    final String ROLE2 = "role2";
    final TSentryPrivilege ROLE2_PRIV1 =
      toTSentryPrivilege("INSERT", "DATABASE", "server1", "db1", "");
    final TSentryPrivilege ROLE2_PRIV2 =
      toTSentryPrivilege("ALL", "SERVER", "server1", "", "");

    createRole(ROLE2);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, ROLE2, Sets.newHashSet(ROLE2_PRIV1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.ROLE, ROLE2, Sets.newHashSet(ROLE2_PRIV2), null);

    final String ROLE3 = "role3";

    createRole(ROLE3);

    allPrivileges = sentryStore.getAllRolesPrivileges();

    // Must return 3 roles, 2 roles has 2 privileges each, 1 role has no privileges
    assertEquals(3, allPrivileges.size());
    assertEquals(2, allPrivileges.get(ROLE1).size());
    assertTrue(allPrivileges.get(ROLE1).contains(ROLE1_PRIV1));
    assertTrue(allPrivileges.get(ROLE1).contains(ROLE1_PRIV2));
    assertEquals(2, allPrivileges.get(ROLE2).size());
    assertTrue(allPrivileges.get(ROLE2).contains(ROLE2_PRIV1));
    assertTrue(allPrivileges.get(ROLE2).contains(ROLE2_PRIV2));
    assertEquals(0, allPrivileges.get(ROLE3).size());
  }

  @Test
  public void testGetAllUsersPrivileges() throws Exception {
    Map<String, Set<TSentryPrivilege>> allPrivileges;

    // The map must be empty (no null) if no roles exist on the system yet
    allPrivileges = sentryStore.getAllUsersPrivileges();
    assertNotNull(allPrivileges);
    assertTrue(allPrivileges.isEmpty());

    final String USER1 = "user1";
    final TSentryPrivilege USER1_PRIV1 =
      toTSentryPrivilege("ALL", "TABLE", "server1", "db1", "table1");
    final TSentryPrivilege USER1_PRIV2 =
      toTSentryPrivilege("SELECT", "TABLE", "server1", "db1", "table2");

    createUser(USER1);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER, USER1, Sets.newHashSet(USER1_PRIV1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER,USER1, Sets.newHashSet(USER1_PRIV2), null);

    final String USER2 = "user2";
    final TSentryPrivilege USER2_PRIV1 =
      toTSentryPrivilege("INSERT", "DATABASE", "server1", "db1", "");
    final TSentryPrivilege USER2_PRIV2 =
      toTSentryPrivilege("ALL", "SERVER", "server1", "", "");

    createUser(USER2);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER,USER2, Sets.newHashSet(USER2_PRIV1), null);
    sentryStore.alterSentryGrantPrivileges(SentryPrincipalType.USER,USER2, Sets.newHashSet(USER2_PRIV2), null);

    final String USER3 = "user3";

    createUser(USER3);

    allPrivileges = sentryStore.getAllUsersPrivileges();

    // Must return 3 roles, 2 roles has 2 privileges each, 1 role has no privileges
    assertEquals(3, allPrivileges.size());
    assertEquals(2, allPrivileges.get(USER1).size());
    assertTrue(allPrivileges.get(USER1).contains(USER1_PRIV1));
    assertTrue(allPrivileges.get(USER1).contains(USER1_PRIV2));
    assertEquals(2, allPrivileges.get(USER2).size());
    assertTrue(allPrivileges.get(USER2).contains(USER2_PRIV1));
    assertTrue(allPrivileges.get(USER2).contains(USER2_PRIV2));
    assertEquals(0, allPrivileges.get(USER3).size());
  }

  @Test
  public void testPersistFullPathsImageWithHugeData() throws Exception {
    Map<String, Collection<String>> authzPaths = new HashMap<>();
    String[] prefixes = {"/user/hive/warehouse/"};
    int dbCount = 10, tableCount = 10, partitionCount = 10, prefixSize;
    prefixSize = StringUtils.countMatches(prefixes[0], "/");

    // Makes sure that authorizable object could be associated
    // with different paths and can be properly persisted into database.
    for(int db_index = 1 ; db_index <= dbCount; db_index++) {
      String db_name = "db" + db_index;
      for( int table_index = 1; table_index <= tableCount; table_index++) {
        Set<String> paths = Sets.newHashSet();
        String table_name = "tb" + table_index;
        String location = prefixes[0] + db_name + "/" + table_name;
        paths.add(location);
        for (int part_index = 1; part_index <= partitionCount; part_index++) {
          paths.add(location + "/" + part_index);
        }
        authzPaths.put(db_name+table_name, paths);
      }
    }
    long notificationID = 110000;
    LOGGER.debug("Before " + Instant.now());
    sentryStore.persistFullPathsImage(authzPaths, notificationID);
    LOGGER.debug("After " + Instant.now());
    PathsUpdate pathsUpdate = sentryStore.retrieveFullPathsImageUpdate(prefixes);
    assertTrue(pathsUpdate.hasFullImage());
    long savedNotificationID = sentryStore.getLastProcessedNotificationID();
    assertEquals(1, pathsUpdate.getImgNum());
    TPathsDump pathDump = pathsUpdate.toThrift().getPathsDump();
    assertNotNull(pathDump);
    Map<Integer, TPathEntry> nodeMap = pathDump.getNodeMap();
    int nodeCount = prefixSize + dbCount + (dbCount * tableCount) +
            (dbCount * tableCount * partitionCount);
    assertTrue(nodeMap.size()  == nodeCount);
    assertEquals(notificationID, savedNotificationID);
  }

  private TSentryPrivilege toTSentryPrivilege(String action, String scope, String server,
    String dbName, String tableName) {
    TSentryPrivilege privilege = new TSentryPrivilege();
    privilege.setPrivilegeScope(scope);
    privilege.setServerName(server);
    privilege.setDbName(dbName);
    privilege.setTableName(tableName);
    privilege.setAction(action);
    privilege.setCreateTime(System.currentTimeMillis());

    return privilege;
  }

  private TSentryPrivilege toTSentryPrivilege(String action, String scope, String server,
    String dbName, String tableName, TSentryGrantOption grantOption) {
    TSentryPrivilege privilege = toTSentryPrivilege(action, scope, server, dbName, tableName);
    privilege.setGrantOption(grantOption);
    return privilege;
  }
}
