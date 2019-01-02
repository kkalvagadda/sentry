/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.sentry.api.service.thrift;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType;
import org.apache.sentry.SentryOwnerInfo;
import org.apache.sentry.api.common.ThriftConstants;
import org.apache.sentry.core.common.exception.SentryGrantDeniedException;
import org.apache.sentry.core.common.exception.SentryUserException;
import org.apache.sentry.core.common.exception.SentrySiteConfigurationException;
import org.apache.sentry.core.common.utils.SentryConstants;
import org.apache.sentry.core.model.db.AccessConstants;
import org.apache.sentry.provider.common.GroupMappingService;
import org.apache.sentry.core.common.exception.SentryGroupNotFoundException;
import org.apache.sentry.core.common.exception.SentryAccessDeniedException;
import org.apache.sentry.core.common.exception.SentryAlreadyExistsException;
import org.apache.sentry.core.common.exception.SentryInvalidInputException;
import org.apache.sentry.core.common.exception.SentryNoSuchObjectException;
import org.apache.sentry.provider.db.SentryPolicyStorePlugin;
import org.apache.sentry.provider.db.SentryPolicyStorePlugin.SentryPluginException;
import org.apache.sentry.core.common.exception.SentryThriftAPIMismatchException;
import org.apache.sentry.provider.db.audit.SentryAuditLogger;
import org.apache.sentry.provider.db.log.util.Constants;
import org.apache.sentry.provider.db.service.persistent.SentryStoreInterface;
import org.apache.sentry.core.common.utils.PolicyStoreConstants.PolicyStoreServerConfig;
import org.apache.sentry.api.service.thrift.validator.GrantPrivilegeRequestValidator;
import org.apache.sentry.api.service.thrift.validator.RevokePrivilegeRequestValidator;
import org.apache.sentry.api.common.SentryServiceUtil;
import org.apache.sentry.service.common.SentryOwnerPrivilegeType;
import org.apache.sentry.service.common.ServiceConstants.ConfUtilties;
import org.apache.sentry.service.common.ServiceConstants.SentryPrincipalType;
import org.apache.sentry.service.common.ServiceConstants.ServerConfig;
import org.apache.sentry.api.common.Status;
import org.apache.sentry.service.thrift.FullUpdateInitializerState;
import org.apache.sentry.service.thrift.SentryStateBank;
import org.apache.sentry.service.thrift.TSentryResponseStatus;
import org.apache.thrift.TException;
import org.apache.log4j.Logger;

import com.codahale.metrics.Timer;
import static com.codahale.metrics.MetricRegistry.name;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.base.Strings;


import static org.apache.sentry.hdfs.Updateable.Update;

@SuppressWarnings("unused")
public class SentryPolicyStoreProcessor implements SentryPolicyService.Iface {
  private static final Logger LOGGER = Logger.getLogger(SentryPolicyStoreProcessor.class);
  private static final Logger AUDIT_LOGGER = Logger.getLogger(Constants.AUDIT_LOGGER_NAME);

  private static final Map<TSentryPrincipalType, SentryPrincipalType> mapOwnerType = ImmutableMap.of(
          TSentryPrincipalType.ROLE, SentryPrincipalType.ROLE,
          TSentryPrincipalType.USER, SentryPrincipalType.USER
  );

  private final String name;
  private final Configuration conf;
  private final SentryStoreInterface sentryStore;
  private final NotificationHandlerInvoker notificationHandlerInvoker;
  private final ImmutableSet<String> adminGroups;
  private SentryMetrics sentryMetrics;
  private final Timer hmsWaitTimer =
          SentryMetrics.getInstance().
                  getTimer(name(SentryPolicyStoreProcessor.class, "hms", "wait"));
  private final SentryAuditLogger audit;

  private List<SentryPolicyStorePlugin> sentryPlugins = new LinkedList<SentryPolicyStorePlugin>();

  SentryPolicyStoreProcessor(String name,
        Configuration conf, SentryStoreInterface store) throws Exception {
    super();
    this.name = name;
    this.conf = conf;
    this.sentryStore = store;
    this.notificationHandlerInvoker = new NotificationHandlerInvoker(conf,
        createHandlers(conf));
    this.audit = new SentryAuditLogger(conf);
    adminGroups = ImmutableSet.copyOf(toTrimedLower(Sets.newHashSet(conf.getStrings(
        ServerConfig.ADMIN_GROUPS, new String[]{}))));
    Iterable<String> pluginClasses = ConfUtilties.CLASS_SPLITTER
        .split(conf.get(ServerConfig.SENTRY_POLICY_STORE_PLUGINS,
            ServerConfig.SENTRY_POLICY_STORE_PLUGINS_DEFAULT).trim());
    for (String pluginClassStr : pluginClasses) {
      Class<?> clazz = conf.getClassByName(pluginClassStr);
      if (!SentryPolicyStorePlugin.class.isAssignableFrom(clazz)) {
        throw new IllegalArgumentException("Sentry Plugin ["
            + pluginClassStr + "] is not a "
            + SentryPolicyStorePlugin.class.getName());
      }
      SentryPolicyStorePlugin plugin = (SentryPolicyStorePlugin)clazz.newInstance();
      plugin.initialize(conf, sentryStore);
      sentryPlugins.add(plugin);
    }
    initMetrics();
  }

  private void initMetrics() {
    sentryMetrics = SentryMetrics.getInstance();
    sentryMetrics.addSentryStoreGauges(sentryStore);
    sentryMetrics.initReporting(conf);
  }

  public void stop() {
    sentryStore.stop();
  }

  public void registerPlugin(SentryPolicyStorePlugin plugin) throws SentryPluginException {
    plugin.initialize(conf, sentryStore);
    sentryPlugins.add(plugin);
  }

  @VisibleForTesting
  static List<NotificationHandler> createHandlers(Configuration conf)
  throws SentrySiteConfigurationException {
    List<NotificationHandler> handlers = Lists.newArrayList();
    Iterable<String> notificationHandlers = Splitter.onPattern("[\\s,]").trimResults()
                                            .omitEmptyStrings().split(conf.get(PolicyStoreServerConfig.NOTIFICATION_HANDLERS, ""));
    for (String notificationHandler : notificationHandlers) {
      Class<?> clazz = null;
      try {
        clazz = Class.forName(notificationHandler);
        if (!NotificationHandler.class.isAssignableFrom(clazz)) {
          throw new SentrySiteConfigurationException("Class " + notificationHandler + " is not a " +
                                                 NotificationHandler.class.getName());
        }
      } catch (ClassNotFoundException e) {
        throw new SentrySiteConfigurationException("Value " + notificationHandler +
                                               " is not a class", e);
      }
      Preconditions.checkNotNull(clazz, "Error class cannot be null");
      try {
        Constructor<?> constructor = clazz.getConstructor(Configuration.class);
        handlers.add((NotificationHandler)constructor.newInstance(conf));
      } catch (Exception e) {
        throw new SentrySiteConfigurationException("Error attempting to create " + notificationHandler, e);
      }
    }
    return handlers;
  }

  @VisibleForTesting
  public Configuration getSentryStoreConf() {
    return conf;
  }

  private static Set<String> toTrimedLower(Set<String> s) {
    Set<String> result = Sets.newHashSet();
    for (String v : s) {
      result.add(v.trim().toLowerCase());
    }
    return result;
  }

  private boolean inAdminGroups(Set<String> requestorGroups) {
    Set<String> trimmedRequestorGroups = toTrimedLower(requestorGroups);
    return !Sets.intersection(adminGroups, trimmedRequestorGroups).isEmpty();
  }
  
  private void authorize(String requestorUser, Set<String> requestorGroups)
  throws SentryAccessDeniedException {
    if (!inAdminGroups(requestorGroups)) {
      String msg = "User: " + requestorUser + " is part of " + requestorGroups +
          " which does not, intersect admin groups " + adminGroups;
      LOGGER.warn(msg);
      throw new SentryAccessDeniedException("Access denied to " + requestorUser);
    }
  }

  @Override
  public TCreateSentryRoleResponse create_sentry_role(
    TCreateSentryRoleRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.createRoleTimer.time();
    TCreateSentryRoleResponse response = new TCreateSentryRoleResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(),
          getRequestorGroups(request.getRequestorUserName()));
      sentryStore.createSentryRole(request.getRoleName());
      response.setStatus(Status.OK());
      notificationHandlerInvoker.create_sentry_role(request, response);
    } catch (SentryAlreadyExistsException e) {
      String msg = "Role: " + request + " already exists.";
      LOGGER.error(msg, e);
      response.setStatus(Status.AlreadyExists(e.getMessage(), e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onCreateRole(request, response);
    return response;
  }

  /**
   * Throws an exception if one of the set of privileges passed as a parameter cannot be granted by
   * the grantor user.
   *
   * <p/> The check is done by looking at the grant option flag each user or user/group role have
   * stored on the DB, and compare it with set of privileges that the user is attempting to grant.
   * If one of the privileges has the grant option disabled, then this method throws an exception
   * to let the caller know it cannot continue with the grant of the privilege.
   *
   * @param grantorUser The user who is attempting to grant the set or privileges.
   * @param checkPrivileges The set of privileges to check.
   * @throws Exception If the user does not have grant privileges.
   */
  private void checkGrantOptionPrivileges(String grantorUser, Set<TSentryPrivilege> checkPrivileges)
    throws Exception {
    Preconditions.checkNotNull(checkPrivileges, "Privileges to check for grant option must not be null.");

    Set<String> groups = getGroupsFromUserName(conf, grantorUser);
    if (groups != null && inAdminGroups(groups)) {
      // grantorUser is part of one of the admin groups, so we permit the grant action
      return;
    }

    // Get all the privileges a user has (either directly granted to the user or through a role
    // which the user belongs too)
    Set<TSentryPrivilege> userPrivileges = sentryStore.listSentryPrivilegesByUsersAndGroups(
      groups, Collections.singleton(grantorUser), new TSentryActiveRoleSet(true, null), null
    );

    if (userPrivileges == null || userPrivileges.isEmpty()) {
      throw new SentryGrantDeniedException(
        String.format("User %s does not have privileges to grant.", grantorUser));
    }

    // Check if each privilege grant will be permitted. Throws an exception in the first privilege
    // that is not permitted.
    for (TSentryPrivilege checkPrivilege : checkPrivileges) {
      boolean hasGrant = false;
      for (TSentryPrivilege p : userPrivileges) {
        if (p.getGrantOption() == TSentryGrantOption.TRUE
            && SentryPolicyStoreUtils.privilegeImplies(p, checkPrivilege)) {
          hasGrant = true;
          break;
        }
      }

      if (!hasGrant) {
        throw new SentryGrantDeniedException(
          String.format("User %s does not have privileges to grant %s.", grantorUser,
            checkPrivilege.getAction().toUpperCase()));
      }
    }
  }

  @Override
  public TAlterSentryRoleGrantPrivilegeResponse alter_sentry_role_grant_privilege
  (TAlterSentryRoleGrantPrivilegeRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.grantTimer.time();
    TAlterSentryRoleGrantPrivilegeResponse response = new TAlterSentryRoleGrantPrivilegeResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      // There should only one field be set
      if ( !(request.isSetPrivileges()^request.isSetPrivilege()) ) {
        throw new SentryUserException("SENTRY API version is not right!");
      }
      // Maintain compatibility for old API: Set privilege field to privileges field
      if (request.isSetPrivilege()) {
        request.setPrivileges(Sets.newHashSet(request.getPrivilege()));
      }

      // Throw an exception if one of the grants is not permitted.
      SentryServiceUtil.checkDbExplicitGrantsPermitted(conf, request.getPrivileges());

      // Throw an exception if the user has not rights to grant one of the grants requested
      checkGrantOptionPrivileges(request.getRequestorUserName(), request.getPrivileges());

      // TODO: now only has SentryPlugin. Once add more SentryPolicyStorePlugins,
      // TODO: need to differentiate the updates for different Plugins.
      Preconditions.checkState(sentryPlugins.size() <= 1);
      Map<TSentryPrivilege, Update> privilegesUpdateMap = new HashMap<>();
      for (SentryPolicyStorePlugin plugin : sentryPlugins) {
        plugin.onAlterSentryRoleGrantPrivilege(request.getRoleName(), request.getPrivileges(), privilegesUpdateMap);
      }

      if (!privilegesUpdateMap.isEmpty()) {
        sentryStore.alterSentryRoleGrantPrivileges(request.getRoleName(),
          request.getPrivileges(), privilegesUpdateMap);
      } else {
        sentryStore.alterSentryRoleGrantPrivileges(request.getRoleName(),
          request.getPrivileges());
      }
      GrantPrivilegeRequestValidator.validate(request);
      response.setStatus(Status.OK());
      response.setPrivileges(request.getPrivileges());
      // Maintain compatibility for old API: Set privilege field to response
      if (response.isSetPrivileges() && response.getPrivileges().size() == 1) {
        response.setPrivilege(response.getPrivileges().iterator().next());
      }
      notificationHandlerInvoker.alter_sentry_role_grant_privilege(request,
              response);
    } catch (SentryNoSuchObjectException e) {
      String msg = "Role: " + request.getRoleName() + " doesn't exist";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryInvalidInputException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.InvalidInput(e.getMessage(), e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onGrantRolePrivilege(request, response);
    return response;
  }

  @Override
  public TAlterSentryRoleRevokePrivilegeResponse alter_sentry_role_revoke_privilege
  (TAlterSentryRoleRevokePrivilegeRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.revokeTimer.time();
    TAlterSentryRoleRevokePrivilegeResponse response = new TAlterSentryRoleRevokePrivilegeResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      // There should only one field be set
      if ( !(request.isSetPrivileges()^request.isSetPrivilege()) ) {
        throw new SentryUserException("SENTRY API version is not right!");
      }
      // Maintain compatibility for old API: Set privilege field to privileges field
      if (request.isSetPrivilege()) {
        request.setPrivileges(Sets.newHashSet(request.getPrivilege()));
      }

      // Throw an exception if the user has not rights to revoke one of the revokes requested
      checkGrantOptionPrivileges(request.getRequestorUserName(), request.getPrivileges());

      // TODO: now only has SentryPlugin. Once add more SentryPolicyStorePlugins,
      // TODO: need to differentiate the updates for different Plugins.
      Preconditions.checkState(sentryPlugins.size() <= 1);
      Map<TSentryPrivilege, Update> privilegesUpdateMap = new HashMap<>();
      for (SentryPolicyStorePlugin plugin : sentryPlugins) {
        plugin.onAlterSentryRoleRevokePrivilege(request.getRoleName(), request.getPrivileges(), privilegesUpdateMap);
      }

      if (!privilegesUpdateMap.isEmpty()) {
        sentryStore.alterSentryRoleRevokePrivileges(request.getRoleName(),
          request.getPrivileges(), privilegesUpdateMap);
      } else {
        sentryStore.alterSentryRoleRevokePrivileges(request.getRoleName(),
          request.getPrivileges());
      }
      RevokePrivilegeRequestValidator.validate(request);
      response.setStatus(Status.OK());
      notificationHandlerInvoker.alter_sentry_role_revoke_privilege(request,
              response);
    } catch (SentryNoSuchObjectException e) {
      StringBuilder msg = new StringBuilder();
      if (request.getPrivileges().size() > 0) {
        for (TSentryPrivilege privilege : request.getPrivileges()) {
          msg.append("Privilege: [server=");
          msg.append(privilege.getServerName());
          msg.append(",db=");
          msg.append(privilege.getDbName());
          msg.append(",table=");
          msg.append(privilege.getTableName());
          msg.append(",URI=");
          msg.append(privilege.getURI());
          msg.append(",action=");
          msg.append(privilege.getAction());
          msg.append("] ");
        }
        msg.append("doesn't exist.");
      }
      LOGGER.error(msg.toString(), e);
      response.setStatus(Status.NoSuchObject(msg.toString(), e));
    } catch (SentryInvalidInputException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.InvalidInput(e.getMessage(), e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onRevokeRolePrivilege(request, response);
    return response;
  }

  @Override
  public TDropSentryRoleResponse drop_sentry_role(
    TDropSentryRoleRequest request)  throws TException {
    final Timer.Context timerContext = sentryMetrics.dropRoleTimer.time();
    TDropSentryRoleResponse response = new TDropSentryRoleResponse();
    TSentryResponseStatus status;
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(),
          getRequestorGroups(request.getRequestorUserName()));

      // TODO: now only has SentryPlugin. Once add more SentryPolicyStorePlugins,
      // TODO: need to differentiate the updates for different Plugins.
      Preconditions.checkState(sentryPlugins.size() <= 1);
      Update update = null;
      for (SentryPolicyStorePlugin plugin : sentryPlugins) {
        update = plugin.onDropSentryRole(request);
      }

      if (update != null) {
        sentryStore.dropSentryRole(request.getRoleName(), update);
      } else {
        sentryStore.dropSentryRole(request.getRoleName());
      }
      response.setStatus(Status.OK());
      notificationHandlerInvoker.drop_sentry_role(request, response);
    } catch (SentryNoSuchObjectException e) {
      String msg = "Role :" + request + " doesn't exist";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onDropRole(request, response);
    return response;
  }

  @Override
  public TAlterSentryRoleAddGroupsResponse alter_sentry_role_add_groups(
    TAlterSentryRoleAddGroupsRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.grantRoleTimer.time();
    TAlterSentryRoleAddGroupsResponse response = new TAlterSentryRoleAddGroupsResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(),
          getRequestorGroups(request.getRequestorUserName()));

      // TODO: now only has SentryPlugin. Once add more SentryPolicyStorePlugins,
      // TODO: need to differentiate the updates for different Plugins.
      Preconditions.checkState(sentryPlugins.size() <= 1);
      Update update = null;
      for (SentryPolicyStorePlugin plugin : sentryPlugins) {
        update = plugin.onAlterSentryRoleAddGroups(request);
      }
      if (update != null) {
        sentryStore.alterSentryRoleAddGroups(request.getRequestorUserName(),
            request.getRoleName(), request.getGroups(), update);
      } else {
        sentryStore.alterSentryRoleAddGroups(request.getRequestorUserName(),
            request.getRoleName(), request.getGroups());
      }
      response.setStatus(Status.OK());
      notificationHandlerInvoker.alter_sentry_role_add_groups(request,
          response);
    } catch (SentryNoSuchObjectException e) {
      String msg = "Role: " + request + " doesn't exist";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onGrantRoleToGroup(request, response);
    return response;
  }

  @Override
  public TAlterSentryRoleAddUsersResponse alter_sentry_role_add_users(
      TAlterSentryRoleAddUsersRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.grantRoleTimer.time();
    TAlterSentryRoleAddUsersResponse response = new TAlterSentryRoleAddUsersResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(), getRequestorGroups(request.getRequestorUserName()));
      sentryStore.alterSentryRoleAddUsers(request.getRoleName(), request.getUsers());
      response.setStatus(Status.OK());
      notificationHandlerInvoker.alter_sentry_role_add_users(request, response);
    } catch (SentryNoSuchObjectException e) {
      String msg = "Role: " + request + " does not exist.";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onGrantRoleToUser(request, response);
    return response;
  }

  @Override
  public TAlterSentryRoleDeleteUsersResponse alter_sentry_role_delete_users(
      TAlterSentryRoleDeleteUsersRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.grantRoleTimer.time();
    TAlterSentryRoleDeleteUsersResponse response = new TAlterSentryRoleDeleteUsersResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(), getRequestorGroups(request.getRequestorUserName()));
      sentryStore.alterSentryRoleDeleteUsers(request.getRoleName(),
              request.getUsers());
      response.setStatus(Status.OK());
      notificationHandlerInvoker.alter_sentry_role_delete_users(request, response);
    } catch (SentryNoSuchObjectException e) {
      String msg = "Role: " + request + " does not exist.";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onRevokeRoleFromUser(request, response);
    return response;
  }

  @Override
  public TAlterSentryRoleDeleteGroupsResponse alter_sentry_role_delete_groups(
    TAlterSentryRoleDeleteGroupsRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.revokeRoleTimer.time();
    TAlterSentryRoleDeleteGroupsResponse response = new TAlterSentryRoleDeleteGroupsResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(),
          getRequestorGroups(request.getRequestorUserName()));

      // TODO: now only has SentryPlugin. Once add more SentryPolicyStorePlugins,
      // TODO: need to differentiate the updates for different Plugins.
      Preconditions.checkState(sentryPlugins.size() <= 1);
      Update update = null;
      for (SentryPolicyStorePlugin plugin : sentryPlugins) {
        update = plugin.onAlterSentryRoleDeleteGroups(request);
      }

      if (update != null) {
        sentryStore.alterSentryRoleDeleteGroups(request.getRoleName(),
          request.getGroups(), update);
      } else {
        sentryStore.alterSentryRoleDeleteGroups(request.getRoleName(),
          request.getGroups());
      }
      response.setStatus(Status.OK());
      notificationHandlerInvoker.alter_sentry_role_delete_groups(request,
          response);
    } catch (SentryNoSuchObjectException e) {
      String msg = "Role: " + request + " does not exist.";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error adding groups to role: " + request;
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }

    audit.onRevokeRoleFromGroup(request, response);
    return response;
  }

  @Override
  public TListSentryRolesResponse list_sentry_roles_by_group(
    TListSentryRolesRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.listRolesByGroupTimer.time();
    TListSentryRolesResponse response = new TListSentryRolesResponse();
    TSentryResponseStatus status;
    Set<TSentryRole> roleSet = new HashSet<TSentryRole>();
    String subject = request.getRequestorUserName();
    boolean checkAllGroups = false;
    try {
      validateClientVersion(request.getProtocol_version());
      Set<String> groups = getRequestorGroups(subject);
      // Don't check admin permissions for listing requestor's own roles
      if (AccessConstants.ALL.equalsIgnoreCase(request.getGroupName())) {
        checkAllGroups = true;
      } else {
        boolean admin = inAdminGroups(groups);
        //Only admin users can list all roles in the system ( groupname = null)
        //Non admin users are only allowed to list only groups which they belong to
        if(!admin && (request.getGroupName() == null || !groups.contains(request.getGroupName()))) {
          throw new SentryAccessDeniedException("Access denied to " + subject);
        } else {
          groups.clear();
          groups.add(request.getGroupName());
        }
      }
      roleSet = sentryStore.getTSentryRolesByGroupName(groups, checkAllGroups);
      response.setRoles(roleSet);
      response.setStatus(Status.OK());
    } catch (SentryNoSuchObjectException e) {
      response.setRoles(roleSet);
      String msg = "Request: " + request + " couldn't be completed, message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  public TListSentryRolesResponse list_sentry_roles_by_user(TListSentryRolesForUserRequest request)
      throws TException {
    final Timer.Context timerContext = sentryMetrics.listRolesByGroupTimer.time();
    TListSentryRolesResponse response = new TListSentryRolesResponse();
    TSentryResponseStatus status;
    Set<TSentryRole> roleSet = new HashSet<TSentryRole>();
    String requestor = request.getRequestorUserName();
    String userName = request.getUserName();
    boolean checkAllGroups = false;
    try {
      validateClientVersion(request.getProtocol_version());
      // userName can't be empty
      if (StringUtils.isEmpty(userName)) {
        throw new SentryAccessDeniedException("The user name can't be empty.");
      }

      Set<String> requestorGroups;
      try {
        requestorGroups = getRequestorGroups(requestor);
      } catch (SentryGroupNotFoundException e) {
        LOGGER.error(e.getMessage(), e);
        response.setStatus(Status.AccessDenied(e.getMessage(), e));
        return response;
      }

      Set<String> userGroups;
      try {
        userGroups = getRequestorGroups(userName);
      } catch (SentryGroupNotFoundException e) {
        LOGGER.error(e.getMessage(), e);
        String msg = "Groups for user " + userName + " do not exist: " + e.getMessage();
        response.setStatus(Status.AccessDenied(msg, e));
        return response;
      }
      boolean isAdmin = inAdminGroups(requestorGroups);

      // Only admin users can list other user's roles in the system
      // Non admin users are only allowed to list only their own roles related user and group
      if (!isAdmin && !userName.equals(requestor)) {
        throw new SentryAccessDeniedException("Access denied to list the roles for " + userName);
      }
      roleSet = sentryStore.getTSentryRolesByUserNames(Sets.newHashSet(userName));
      response.setRoles(roleSet);
      response.setStatus(Status.OK());
    } catch (SentryNoSuchObjectException e) {
      response.setRoles(roleSet);
      String msg = "Role: " + request + " couldn't be retrieved.";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  @Override
  public TListSentryPrivilegesResponse list_sentry_privileges_by_role(
      TListSentryPrivilegesRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.listPrivilegesByRoleTimer.time();
    TListSentryPrivilegesResponse response = new TListSentryPrivilegesResponse();
    TSentryResponseStatus status;
    Set<TSentryPrivilege> privilegeSet = new HashSet<TSentryPrivilege>();
    String subject = request.getRequestorUserName();

    // The 'roleName' parameter is deprecated in Sentry 2.x. If the new 'entityName' is not
    // null, then use it to get the role name otherwise fall back to the old 'roleName' which
    // is required to be set.
    String roleName = (request.getPrincipalName() != null)
      ? request.getPrincipalName() : request.getRoleName();

    try {
      validateClientVersion(request.getProtocol_version());
      Set<String> groups = getRequestorGroups(subject);
      Boolean admin = inAdminGroups(groups);
      if(!admin) {
        Set<String> roleNamesForGroups = toTrimedLower(sentryStore.getRoleNamesForGroups(groups));
        if(!roleNamesForGroups.contains(roleName.trim().toLowerCase())) {
          throw new SentryAccessDeniedException("Access denied to " + subject);
        }
      }
      if (request.isSetAuthorizableHierarchy()) {
        TSentryAuthorizable authorizableHierarchy = request.getAuthorizableHierarchy();
        privilegeSet = sentryStore.getTSentryPrivileges(SentryPrincipalType.ROLE, Sets.newHashSet(roleName), authorizableHierarchy);
      } else {
        privilegeSet = sentryStore.getAllTSentryPrivilegesByRoleName(roleName);
      }
      response.setPrivileges(privilegeSet);
      response.setStatus(Status.OK());
    } catch (SentryNoSuchObjectException e) {
      response.setPrivileges(privilegeSet);
      String msg = "Privilege: " + request + " couldn't be retrieved.";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  /**
   * This method is used to check that required parameters marked as optional in thrift are
   * not null.
   *
   * @param param The object parameter marked as optional to check.
   * @param message The warning message to log and return to the client.
   * @return Null if the parameter is not null, otherwise a InvalidInput status that can be
   * used to return to the client.
   */
  private TSentryResponseStatus checkRequiredParameter(Object param, String message) {
    if (param == null) {
      LOGGER.warn(message);
      return Status.InvalidInput(message, new SentryInvalidInputException(message));
    }

    return null;
  }

  @Override
  public TListSentryPrivilegesResponse list_sentry_privileges_by_user(
    TListSentryPrivilegesRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.listPrivilegesByUserTimer.time();
    TListSentryPrivilegesResponse response = new TListSentryPrivilegesResponse();
    Set<TSentryPrivilege> privilegeSet = new HashSet<TSentryPrivilege>();
    String subject = request.getRequestorUserName();

    // The 'principalName' parameter is made optional in thrift, so we need to check that is not
    // null before proceed.
    TSentryResponseStatus status =
      checkRequiredParameter(request.getPrincipalName(),
                             "principalName parameter must not be null");
    if (status != null) {
      response.setStatus(status);
      return response;
    }

    String userName = request.getPrincipalName().trim();

    try {
      validateClientVersion(request.getProtocol_version());

      // To allow listing the privileges, the requestor user must be part of the admins group, or
      // the requestor user must be the same user requesting privileges for.
      Set<String> groups = getRequestorGroups(subject);
      Boolean admin = inAdminGroups(groups);
      if(!admin && !userName.equalsIgnoreCase(subject)) {
        throw new SentryAccessDeniedException("Access denied to " + subject);
      }

      if (request.isSetAuthorizableHierarchy()) {
        TSentryAuthorizable authorizableHierarchy = request.getAuthorizableHierarchy();
        privilegeSet = sentryStore.getTSentryPrivileges(SentryPrincipalType.USER, Sets.newHashSet(userName), authorizableHierarchy);
      } else {
        privilegeSet = sentryStore.getAllTSentryPrivilegesByUserName(userName);
      }

      response.setPrivileges(privilegeSet);
      response.setStatus(Status.OK());
    } catch (SentryNoSuchObjectException e) {
      response.setPrivileges(privilegeSet);
      String msg = "Privilege: " + request + " couldn't be retrieved.";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  @Override
  public TListSentryPrivilegesResponse list_sentry_privileges_by_user_and_itsgroups(
          TListSentryPrivilegesRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.listPrivilegesForUserTimer.time();
    TListSentryPrivilegesResponse response = new TListSentryPrivilegesResponse();

    // The 'principalName' parameter is made optional in thrift, so we need to
    // check that is not null before proceed.
    TSentryResponseStatus status = checkRequiredParameter(request.getPrincipalName(),
                                                          "principalName parameter must not be null");
    if (status != null) {
      response.setStatus(status);
      return response;
    }

    String requestor = request.getRequestorUserName();
    String principalName = request.getPrincipalName().trim();
    Set<TSentryPrivilege> privilegeSet = new HashSet<>();

    try {
      validateClientVersion(request.getProtocol_version());

      // To allow listing the privileges, the requestor user must be part of
      // the admins group, or the requestor user must be the same user requesting
      // privileges for.
      Set<String> requestorGroups = getRequestorGroups(requestor);
      Boolean admin = inAdminGroups(requestorGroups);
      if(!admin && !principalName.equalsIgnoreCase(requestor)) {
        throw new SentryAccessDeniedException("Access denied to " + requestor);
      }

      // Get the groups the user is associated with.
      Set<String> principalGroups;
      if (principalName.equals(requestor)) {
        principalGroups = requestorGroups;
      } else {
        principalGroups = getRequestorGroups(principalName);
      }
      Set<String> principalUsers = new HashSet<>();
      principalUsers.add(principalName);
      privilegeSet.addAll(sentryStore.listSentryPrivilegesByUsersAndGroups(
              principalGroups, principalUsers,
              new TSentryActiveRoleSet(true, null),
              request.getAuthorizableHierarchy()));
      response.setPrivileges(privilegeSet);
      response.setStatus(Status.OK());
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryInvalidInputException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.InvalidInput(e.getMessage(), e));
    } catch (SentryUserException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  /**
   * This method was created specifically for ProviderBackend.getPrivileges() and is not meant
   * to be used for general privilege retrieval. More details in the .thrift file.
   */
  @Override
  public TListSentryPrivilegesForProviderResponse list_sentry_privileges_for_provider(
      TListSentryPrivilegesForProviderRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.listPrivilegesForProviderTimer.time();
    TListSentryPrivilegesForProviderResponse response = new TListSentryPrivilegesForProviderResponse();
    response.setPrivileges(new HashSet<String>());
    try {
      validateClientVersion(request.getProtocol_version());
      Set<String> privilegesForProvider =
          sentryStore.listSentryPrivilegesForProvider(request.getGroups(), request.getUsers(),
              request.getRoleSet(), request.getAuthorizableHierarchy());
      response.setPrivileges(privilegesForProvider);
      if (privilegesForProvider == null
          || privilegesForProvider.size() == 0
          && request.getAuthorizableHierarchy() != null
          && sentryStore.hasAnyServerPrivileges(request.getGroups(), request.getUsers(),
              request.getRoleSet(), request.getAuthorizableHierarchy().getServer())) {

        // REQUIRED for ensuring 'default' Db is accessible by any user
        // with privileges to atleast 1 object with the specific server as root

        // Need some way to specify that even though user has no privilege
        // For the specific AuthorizableHierarchy.. he has privilege on
        // atleast 1 object in the server hierarchy
        HashSet<String> serverPriv = Sets.newHashSet("server=+");
        response.setPrivileges(serverPriv);
      }
      response.setStatus(Status.OK());
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  // retrieve the group mapping for the given user name
  private Set<String> getRequestorGroups(String userName)
      throws SentryUserException {
    return getGroupsFromUserName(this.conf, userName);
  }

  public static Set<String> getGroupsFromUserName(Configuration conf,
      String userName) throws SentryUserException {
    String groupMapping = conf.get(ServerConfig.SENTRY_STORE_GROUP_MAPPING,
        ServerConfig.SENTRY_STORE_GROUP_MAPPING_DEFAULT);
    String authResoruce = conf
        .get(ServerConfig.SENTRY_STORE_GROUP_MAPPING_RESOURCE);

    // load the group mapping provider class
    GroupMappingService groupMappingService;
    try {
      Constructor<?> constrctor = Class.forName(groupMapping)
          .getDeclaredConstructor(Configuration.class, String.class);
      constrctor.setAccessible(true);
      groupMappingService = (GroupMappingService) constrctor
          .newInstance(new Object[] { conf, authResoruce });
    } catch (NoSuchMethodException e) {
      throw new SentryUserException("Unable to instantiate group mapping", e);
    } catch (SecurityException e) {
      throw new SentryUserException("Unable to instantiate group mapping", e);
    } catch (ClassNotFoundException e) {
      throw new SentryUserException("Unable to instantiate group mapping", e);
    } catch (InstantiationException e) {
      throw new SentryUserException("Unable to instantiate group mapping", e);
    } catch (IllegalAccessException e) {
      throw new SentryUserException("Unable to instantiate group mapping", e);
    } catch (IllegalArgumentException e) {
      throw new SentryUserException("Unable to instantiate group mapping", e);
    } catch (InvocationTargetException e) {
      throw new SentryUserException("Unable to instantiate group mapping", e);
    }
    return groupMappingService.getGroups(userName);
  }

  @Override
  public TDropPrivilegesResponse drop_sentry_privilege(
      TDropPrivilegesRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.dropPrivilegeTimer.time();
    TDropPrivilegesResponse response = new TDropPrivilegesResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(), adminGroups);

      // TODO: now only has SentryPlugin. Once add more SentryPolicyStorePlugins,
      // TODO: need to differentiate the updates for different Plugins.
      Preconditions.checkState(sentryPlugins.size() <= 1);
      Update update = null;
      for (SentryPolicyStorePlugin plugin : sentryPlugins) {
        update = plugin.onDropSentryPrivilege(request);
      }
      if (update != null) {
        sentryStore.dropPrivilege(request.getAuthorizable(), update);
      } else {
        sentryStore.dropPrivilege(request.getAuthorizable());
      }
      response.setStatus(Status.OK());
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: "
          + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  @Override
  public TRenamePrivilegesResponse rename_sentry_privilege(
      TRenamePrivilegesRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.renamePrivilegeTimer.time();
    TRenamePrivilegesResponse response = new TRenamePrivilegesResponse();
    try {
      validateClientVersion(request.getProtocol_version());
      authorize(request.getRequestorUserName(), adminGroups);

      // TODO: now only has SentryPlugin. Once add more SentryPolicyStorePlugins,
      // TODO: need to differentiate the updates for different Plugins.
      Preconditions.checkState(sentryPlugins.size() <= 1);
      Update update = null;
      for (SentryPolicyStorePlugin plugin : sentryPlugins) {
        update = plugin.onRenameSentryPrivilege(request);
      }
      if (update != null) {
        sentryStore.renamePrivilege(request.getOldAuthorizable(),
            request.getNewAuthorizable(), update);
      } else {
        sentryStore.renamePrivilege(request.getOldAuthorizable(),
            request.getNewAuthorizable());
      }
      response.setStatus(Status.OK());
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (SentryInvalidInputException e) {
      response.setStatus(Status.InvalidInput(e.getMessage(), e));
    }
    catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: "
          + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.close();
    }
    return response;
  }

  @Override
  public TListSentryPrivilegesByAuthResponse list_sentry_privileges_by_authorizable(
      TListSentryPrivilegesByAuthRequest request) throws TException {
    final Timer.Context timerContext = sentryMetrics.listPrivilegesByAuthorizableTimer.time();
    TListSentryPrivilegesByAuthResponse response = new TListSentryPrivilegesByAuthResponse();
    Map<TSentryAuthorizable, TSentryPrivilegeMap> authRoleMap = Maps.newHashMap();
    Map<TSentryAuthorizable, TSentryPrivilegeMap> authUserMap = Maps.newHashMap();
    String subject = request.getRequestorUserName();
    Set<String> requestedGroups = request.getGroups();
    Set<String> requestedUsers = request.getUsers();
    TSentryActiveRoleSet requestedRoleSet = request.getRoleSet();
    try {
      validateClientVersion(request.getProtocol_version());
      Set<String> memberGroups = getRequestorGroups(subject);
      if(!inAdminGroups(memberGroups)) {
        // disallow non-admin to lookup groups that they are not part of
        if (requestedGroups != null && !requestedGroups.isEmpty()) {
          for (String requestedGroup : requestedGroups) {
            if (!memberGroups.contains(requestedGroup)) {
              // if user doesn't belong to one of the requested group then raise error
              throw new SentryAccessDeniedException("Access denied to " + subject);
            }
          }
        } else {
          // non-admin's search is limited to it's own groups
          requestedGroups = memberGroups;
        }

        // disallow non-admin to lookup roles that they are not part of
        if (requestedRoleSet != null && !requestedRoleSet.isAll()) {
          Set<String> roles = toTrimedLower(sentryStore
              .getRoleNamesForGroups(memberGroups));
          for (String role : toTrimedLower(requestedRoleSet.getRoles())) {
            if (!roles.contains(role)) {
              throw new SentryAccessDeniedException("Access denied to "
                  + subject);
            }
          }
        }

        // disallow non-admin to lookup users that they are not part of
        if (requestedUsers != null && !requestedUsers.isEmpty()) {
          for (String requestedUser : requestedUsers) {
            if (!requestedUser.equalsIgnoreCase(subject)) {
              // if user doesn't is not requesting its own user privileges then raise error
              throw new SentryAccessDeniedException("Access denied to " + subject);
            }
          }
        }
      }

      // Return user and role privileges found per authorizable object
      for (TSentryAuthorizable authorizable : request.getAuthorizableSet()) {
        authRoleMap.put(authorizable, sentryStore
            .listSentryPrivilegesByAuthorizable(requestedGroups,
                request.getRoleSet(), authorizable, inAdminGroups(memberGroups)));

        authUserMap.put(authorizable, sentryStore
          .listSentryPrivilegesByAuthorizableForUser(requestedUsers, authorizable,
            inAdminGroups(memberGroups)));
      }
      response.setPrivilegesMapByAuth(authRoleMap);
      response.setPrivilegesMapByAuthForUsers(authUserMap);
      response.setStatus(Status.OK());
      // TODO : Sentry - HDFS : Have to handle this
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: "
          + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    } finally {
      timerContext.stop();
    }
    return response;
  }

  /**
   * Respond to a request for a config value in the sentry server.  The client
   * can request any config value that starts with "sentry." and doesn't contain
   * "keytab".
   * @param request Contains config parameter sought and default if not found
   * @return The response, containing the value and status
   * @throws TException
   */
  @Override
  public TSentryConfigValueResponse get_sentry_config_value(
          TSentryConfigValueRequest request) throws TException {

    final String requirePattern = "^sentry\\..*";
    final String excludePattern = ".*keytab.*|.*\\.jdbc\\..*|.*password.*";

    TSentryConfigValueResponse response = new TSentryConfigValueResponse();
    String attr = request.getPropertyName();

    try {
      validateClientVersion(request.getProtocol_version());
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    }
    // Only allow config parameters like...
    if (!Pattern.matches(requirePattern, attr) ||
        Pattern.matches(excludePattern, attr)) {
      String msg = "Attempted access of the configuration property " + attr +
              " was denied";
      LOGGER.error(msg);
      response.setStatus(Status.AccessDenied(msg,
              new SentryAccessDeniedException(msg)));
      return response;
    }

    response.setValue(conf.get(attr,request.getDefaultValue()));
    response.setStatus(Status.OK());
    return response;
  }

  @VisibleForTesting
  static void validateClientVersion(int protocolVersion) throws SentryThriftAPIMismatchException {
    if (ThriftConstants.TSENTRY_SERVICE_VERSION_CURRENT != protocolVersion) {
      String msg = "Sentry thrift API protocol version mismatch: Client thrift version " +
          "is: " + protocolVersion + " , server thrift verion " +
              "is " + ThriftConstants.TSENTRY_SERVICE_VERSION_CURRENT;
      throw new SentryThriftAPIMismatchException(msg);
    }
  }

  // get the sentry mapping data and return the data with map structure
  @Override
  @SuppressWarnings("PMD.AvoidBranchingStatementAsLastInLoop")
  public TSentryExportMappingDataResponse export_sentry_mapping_data(
      TSentryExportMappingDataRequest request) throws TException {
    TSentryExportMappingDataResponse response = new TSentryExportMappingDataResponse();
    try {
      String requestor = request.getRequestorUserName();
      Set<String> memberGroups = getRequestorGroups(requestor);
      String databaseName = null;
      String tableName = null;

      if(request.getAuthorizables() != null && request.getAuthorizables().size() > 0) {
        for (TSentryAuthorizable authorizable : request.getAuthorizables()) {
          databaseName = authorizable.getDb();
          tableName = authorizable.getTable();
          // TODO This change is added to maintain the current functionality.
          // This code will be updated sentry sentry client/server are enhanced to handle export og permissions for
          // multiple authorizables.
          break;
        }
      }
      if (!inAdminGroups(memberGroups)) {
        // disallow non-admin to import the metadata of sentry
        throw new SentryAccessDeniedException("Access denied to " + requestor
            + " for export the metadata of sentry.");
      }
      TSentryMappingData tSentryMappingData = new TSentryMappingData();
      Map<String, Set<TSentryPrivilege>> rolePrivileges =
          sentryStore.getRoleNameTPrivilegesMap(databaseName, tableName);
      tSentryMappingData.setRolePrivilegesMap(rolePrivileges);
      Set<String> roleNames = rolePrivileges.keySet();
      // roleNames should be null if databaseName == null and tableName == null
      if (databaseName == null && tableName == null) {
        roleNames = null;
      }
      List<Map<String, Set<String>>> mapList = sentryStore.getGroupUserRoleMapList(
          roleNames);
      tSentryMappingData.setGroupRolesMap(mapList.get(
          SentryConstants.INDEX_GROUP_ROLES_MAP));
      tSentryMappingData.setUserRolesMap(mapList.get(SentryConstants.INDEX_USER_ROLES_MAP));

      response.setMappingData(tSentryMappingData);
      response.setStatus(Status.OK());
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setMappingData(new TSentryMappingData());
      response.setStatus(Status.RuntimeError(msg, e));
    }
    return response;
  }

  // get the sentry mapping data and return the data with map structure
  @Override
  @SuppressWarnings("PMD.AvoidBranchingStatementAsLastInLoop")
  public TSentryExportPermissionsMappingDataResponse export_sentry_permission_mapping_data(
          TSentryExportMappingDataRequest request) throws TException {
    TSentryExportPermissionsMappingDataResponse response = new TSentryExportPermissionsMappingDataResponse();
    try {
      String requestor = request.getRequestorUserName();
      Set<String> memberGroups = getRequestorGroups(requestor);
      String databaseName = null;
      String tableName = null;

      if(request.getAuthorizables() != null && request.getAuthorizables().size() > 0) {
        for (TSentryAuthorizable authorizable : request.getAuthorizables()) {
          databaseName = authorizable.getDb();
          tableName = authorizable.getTable();
          // TODO This change is added to maintain the current functionality.
          // This code will be updated sentry sentry client/server are enhanced to handle export og permissions for
          // multiple authorizables.
          break;
        }
      }
      if (!inAdminGroups(memberGroups)) {
        // disallow non-admin to import the metadata of sentry
        throw new SentryAccessDeniedException("Access denied to " + requestor
                + " for export the metadata of sentry.");
      }
      TSentryPermissionMappingData tSentryPermissionMappingData = new TSentryPermissionMappingData();
      Map<TSentryAuthorizable, Map<TSentryPrincipal, List<TPrivilege>>> mappingData =
              sentryStore.getPrivilegesMap (databaseName, tableName);

      tSentryPermissionMappingData.setPermissionMapping(mappingData);

      response.setMappingData(tSentryPermissionMappingData);
      response.setStatus(Status.OK());
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setMappingData(new TSentryPermissionMappingData());
      response.setStatus(Status.RuntimeError(msg, e));
    }
    return response;
  }


  // import the sentry mapping data
  @Override
  public TSentryImportMappingDataResponse import_sentry_mapping_data(
      TSentryImportMappingDataRequest request) throws TException {
    TSentryImportMappingDataResponse response = new TSentryImportMappingDataResponse();
    try {
      String requestor = request.getRequestorUserName();
      Set<String> memberGroups = getRequestorGroups(requestor);
      if (!inAdminGroups(memberGroups)) {
        // disallow non-admin to import the metadata of sentry
        throw new SentryAccessDeniedException("Access denied to " + requestor
            + " for import the metadata of sentry.");
      }
      sentryStore.importSentryMetaData(request.getMappingData(), request.isOverwriteRole());
      response.setStatus(Status.OK());
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryGroupNotFoundException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryInvalidInputException e) {
      String msg = "Invalid input privilege object";
      LOGGER.error(msg, e);
      response.setStatus(Status.InvalidInput(msg, e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    }
    return response;
  }

  @Override
  public TSentrySyncIDResponse sentry_sync_notifications(TSentrySyncIDRequest request)
          throws TException {
    TSentrySyncIDResponse response = new TSentrySyncIDResponse();
    try (Timer.Context timerContext = hmsWaitTimer.time()) {
      // Wait until Sentry Server processes specified HMS Notification ID.
      response.setId(sentryStore.getCounterWait().waitFor(request.getId()));
      response.setStatus(Status.OK());
    } catch (InterruptedException e) {
      String msg = String.format("wait request for id %d is interrupted",
              request.getId());
      LOGGER.error(msg, e);
      response.setId(0);
      response.setStatus(Status.RuntimeError(msg, e));
      Thread.currentThread().interrupt();
    } catch (TimeoutException e) {
      String msg = String.format("timed out wait request for id %d", request.getId());
      LOGGER.warn(msg, e);
      response.setId(0);
      response.setStatus(Status.RuntimeError(msg, e));
    }
    return response;
  }

  @Override
  public TSentryHmsEventNotificationResponse sentry_notify_hms_event
          (TSentryHmsEventNotification request) throws TException {
    TSentryHmsEventNotificationResponse response = new TSentryHmsEventNotificationResponse();
    EventType eventType = EventType.valueOf(request.getEventType());
    try (Timer.Context timerContext = sentryMetrics.notificationProcessTimer.time()) {
      switch (eventType) {
        case CREATE_DATABASE:
        case CREATE_TABLE:
          // Wait till Sentry server processes HMS Notification Event.
          if(request.getId() > 0) {
            response.setId(syncEventId(request.getId()));
          } else {
            response.setId(0L);
          }
          //Grant privilege to the owner.
          grantOwnerPrivilege(request);
          break;
        case DROP_DATABASE:
        case DROP_TABLE:
          // Wait till Sentry server processes HMS Notification Event.
          if(request.getId() > 0) {
            response.setId(syncEventId(request.getId()));
          } else {
            response.setId(0L);
          }
          // Owner privileges for the database and tables that are dropped are cleaned-up when
          // sentry fetches and process the DROP_DATABASE and DROP_TABLE notifications.
          break;
        case ALTER_TABLE:
          /* Alter table event is notified to sentry when either of below is observed.
             together.
             1. Owner Update
             2. Table Rename
          */
        // case ALTER_DATABASE: TODO: Enable once HIVE-18031 is available
          // Wait till Sentry server processes HMS Notification Event.
          if(request.getId() > 0) {
            response.setId(syncEventId(request.getId()));
          } else {
            response.setId(0L);
          }
          // When owner is updated, revoke owner privilege from old owners and grant one to the new owner.
          updateOwnerPrivilege(request);
          break;
        default:
         LOGGER.info("Processing HMS Event of Type: " + eventType.toString() + " skipped");
      }
      response.setStatus(Status.OK());
    } catch (SentryNoSuchObjectException e) {
      String msg = request.getOwnerType().toString() + ": " + request.getOwnerName() + " doesn't exist";
      LOGGER.error(msg, e);
      response.setStatus(Status.NoSuchObject(msg, e));
    } catch (SentryInvalidInputException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.InvalidInput(e.getMessage(), e));
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Unknown error for request: " + request + ", message: " + e.getMessage();
      LOGGER.error(msg, e);
        response.setStatus(Status.RuntimeError(msg, e));
    }

    return response;
  }

  @Override
  public TSentryPrivilegesResponse list_roles_privileges(TSentryPrivilegesRequest request)
    throws TException {
    TSentryPrivilegesResponse response = new TSentryPrivilegesResponse();
    String requestor = request.getRequestorUserName();

    try (Timer.Context timerContext = sentryMetrics.listRolesPrivilegesTimer.time()) {
      // Throws SentryThriftAPIMismatchException if protocol version mismatch
      validateClientVersion(request.getProtocol_version());

      // Throws SentryUserException with the Status.ACCESS_DENIED status if the requestor
      // is not an admin. Only admins can request all roles and privileges of the system.
      authorize(requestor, getRequestorGroups(requestor));

      response.setPrivilegesMap(sentryStore.getAllRolesPrivileges());
      response.setStatus(Status.OK());
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryUserException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Could not read roles and privileges from the database: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    }

    return response;
  }

  @Override
  public TSentryPrivilegesResponse list_users_privileges(TSentryPrivilegesRequest request)
    throws TException {
    TSentryPrivilegesResponse response = new TSentryPrivilegesResponse();
    String requestor = request.getRequestorUserName();

    try (Timer.Context timerContext = sentryMetrics.listUsersPrivilegesTimer.time()) {
      // Throws SentryThriftAPIMismatchException if protocol version mismatch
      validateClientVersion(request.getProtocol_version());

      // Throws SentryUserException with the Status.ACCESS_DENIED status if the requestor
      // is not an admin. Only admins can request all users and privileges of the system.
      authorize(requestor, getRequestorGroups(requestor));

      response.setPrivilegesMap(sentryStore.getAllUsersPrivileges());
      response.setStatus(Status.OK());
    } catch (SentryThriftAPIMismatchException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.THRIFT_VERSION_MISMATCH(e.getMessage(), e));
    } catch (SentryAccessDeniedException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (SentryUserException e) {
      LOGGER.error(e.getMessage(), e);
      response.setStatus(Status.AccessDenied(e.getMessage(), e));
    } catch (Exception e) {
      String msg = "Could not read users and privileges from the database: " + e.getMessage();
      LOGGER.error(msg, e);
      response.setStatus(Status.RuntimeError(msg, e));
    }

    return response;
  }

  /**
   * Grants owner privilege  to an authorizable.
   *
   * Privilege is granted based on the information in TSentryHmsEventNotification
   * @param request TSentryHmsEventNotification
   * @throws Exception when there an exception while sending/processing the request.
   */
  private void grantOwnerPrivilege(TSentryHmsEventNotification request) throws Exception {
    if (Strings.isNullOrEmpty(request.getOwnerName()) || (request.getOwnerType().getValue() == 0)) {
      LOGGER.debug(String.format("Owner Information not provided for Operation: [%s], Not adding owner privilege for" +
              " object: [%s].[%s]", request.getEventType(), request.getAuthorizable().getDb(),
              request.getAuthorizable().getTable()));
      return;
    }

    TSentryPrivilege ownerPrivilege = constructOwnerPrivilege(request.getAuthorizable());
    if (ownerPrivilege == null) {
      LOGGER.debug("Owner privilege is not added");
      return;
    }

    SentryPrincipalType principalType = getSentryPrincipalType(request.getOwnerType());
    if (principalType == null) {
      String error = "Invalid owner type : " + request.getEventType();
      LOGGER.error(error);
      throw new SentryInvalidInputException(error);
    }

    Preconditions.checkState(sentryPlugins.size() <= 1);
    Set<TSentryPrivilege> privSet = Collections.singleton(ownerPrivilege);
    Map<TSentryPrivilege, Update> privilegesUpdateMap = new HashMap<>();
    getOwnerPrivilegeUpdateForGrant(request.getOwnerName(), request.getOwnerType(), privSet, privilegesUpdateMap);

    // Grants owner privilege to the principal
    try {
      sentryStore.alterSentryGrantOwnerPrivilege(request.getOwnerName(), principalType,
              ownerPrivilege, privilegesUpdateMap.get(ownerPrivilege));

      audit.onGrantOwnerPrivilege(Status.OK(), request.getRequestorUserName(),
        request.getOwnerType(), request.getOwnerName(), request.getAuthorizable());
    } catch (Exception e) {
      String msg = "Owner privilege for " + request.getAuthorizable() + " could not be granted: " + e.getMessage();
      audit.onGrantOwnerPrivilege(Status.RuntimeError(msg, e), request.getRequestorUserName(),
        request.getOwnerType(), request.getOwnerName(), request.getAuthorizable());

      throw e;
    }

    //TODO Implement notificationHandlerInvoker API for granting user priv and invoke it.
  }

  /**
   * Alters owner privilege of an authorizable.
   *
   * Revoke all the owner privileges on the authorizable and grants new owner privilege.
   * @param request Sentry HMS Event Notification
   * @throws Exception when there an exception while sending/processing the request.
   */
  private void updateOwnerPrivilege(TSentryHmsEventNotification request) throws Exception {
    if (Strings.isNullOrEmpty(request.getOwnerName()) || (request.getOwnerType().getValue() == 0)) {
      LOGGER.debug(String.format("Owner Information not provided for Operation: [%s], Not revoking owner privilege for" +
                      " object: [%s].[%s]", request.getEventType(), request.getAuthorizable().getDb(),
              request.getAuthorizable().getTable()));
      return;
    }

    TSentryPrivilege ownerPrivilege = constructOwnerPrivilege(request.getAuthorizable());
    if (ownerPrivilege == null) {
      LOGGER.debug("Owner privilege is not added");
      return;
    }

    SentryPrincipalType principalType = getSentryPrincipalType(request.getOwnerType());
    if(principalType == null ) {
      String error = "Invalid owner type : " + request.getEventType();
      LOGGER.error(error);
      throw new SentryInvalidInputException(error);
    }

    Set<TSentryPrivilege> privSet = Collections.singleton(ownerPrivilege);
    Preconditions.checkState(sentryPlugins.size() <= 1);
    Map<TSentryPrivilege, Update> privilegesUpdateMap = new HashMap<>();
    List<Update> updateList = new ArrayList<>();
    List<SentryOwnerInfo> ownerInfoList = sentryStore.listOwnersByAuthorizable(request.getAuthorizable());
    // Creating updates for deleting all the old owner privileges
    // There should only one owner privilege for an authorizable but the current schema
    // doesn't have constraints to limit it. It is possible to have multiple owners for an authorizable (which is unlikely)
    // This logic makes sure of revoking all the owner privilege.
    for (SentryPolicyStorePlugin plugin : sentryPlugins) {
      for (SentryOwnerInfo ownerInfo : ownerInfoList) {
        if (ownerInfo.getOwnerType().equals(SentryPrincipalType.USER)) {
          plugin.onAlterSentryUserRevokePrivilege(ownerInfo.getOwnerName(), privSet, privilegesUpdateMap);
          updateList.add(privilegesUpdateMap.get(ownerPrivilege));
          privilegesUpdateMap.clear();
        } else if (ownerInfo.getOwnerType().equals(SentryPrincipalType.ROLE)) {
          plugin.onAlterSentryRoleRevokePrivilege(request.getOwnerName(), privSet, privilegesUpdateMap);
          updateList.add(privilegesUpdateMap.get(ownerPrivilege));
          privilegesUpdateMap.clear();
        }
      }
    }
    getOwnerPrivilegeUpdateForGrant(request.getOwnerName(), request.getOwnerType(), privSet, privilegesUpdateMap);
    updateList.add(privilegesUpdateMap.get(ownerPrivilege));

    // Revokes old owner privileges and grants owner privilege for new owner.
    try {
      sentryStore.updateOwnerPrivilege(request.getAuthorizable(), request.getOwnerName(),
        principalType, updateList);

      audit.onTransferOwnerPrivilege(Status.OK(), request.getRequestorUserName(),
        request.getOwnerType(), request.getOwnerName(), request.getAuthorizable());
    } catch (Exception e) {
      String msg = "Owner privilege for " + request.getAuthorizable() + " could not be granted: " + e.getMessage();

      audit.onTransferOwnerPrivilege(Status.RuntimeError(msg, e), request.getRequestorUserName(),
        request.getOwnerType(), request.getOwnerName(), request.getAuthorizable());

      throw e;
    }

    //TODO Implement notificationHandlerInvoker API for granting user priv and invoke it.
  }

  /**
   * Adds privilege update for grant into the privilegesUpdateMap provided.
   * @param ownerName
   * @param ownerType
   * @param privSet
   * @param privilegesUpdateMap
   * @throws Exception
   */
  private void getOwnerPrivilegeUpdateForGrant(String ownerName, TSentryPrincipalType ownerType,
      Set<TSentryPrivilege> privSet,
      Map<TSentryPrivilege, Update> privilegesUpdateMap) throws Exception {
    for (SentryPolicyStorePlugin plugin : sentryPlugins) {
      switch (ownerType) {
        case ROLE:
          plugin.onAlterSentryRoleGrantPrivilege(ownerName, privSet, privilegesUpdateMap);
          break;
        case USER:
          plugin.onAlterSentryUserGrantPrivilege(ownerName, privSet, privilegesUpdateMap);
          break;
        default:
          String error = "Invalid owner type : " + ownerType;
          LOGGER.error(error);
          throw new SentryInvalidInputException(error);
      }
    }
  }

  /**
   * This API constructs (@Link TSentryPrivilege} for authorizable provided
   * based on the configurations.
   *
   * @param authorizable for which owner privilege should be constructed.
   * @return null if owner privilege can not be constructed, else instance of {@Link TSentryPrivilege}
   */
  TSentryPrivilege constructOwnerPrivilege(TSentryAuthorizable authorizable) {
    SentryOwnerPrivilegeType ownerPrivilegeType = SentryOwnerPrivilegeType.get(conf);
    if(ownerPrivilegeType == SentryOwnerPrivilegeType.NONE) {
      return null;
    }

    if(Strings.isNullOrEmpty(authorizable.getDb())) {
      LOGGER.error("Received authorizable with out DB Name");
      return null;
    }

    TSentryPrivilege ownerPrivilege = new TSentryPrivilege();
    ownerPrivilege.setServerName(authorizable.getServer());
    ownerPrivilege.setDbName(authorizable.getDb());
    if(!Strings.isNullOrEmpty(authorizable.getTable())) {
      ownerPrivilege.setTableName(authorizable.getTable());
      ownerPrivilege.setPrivilegeScope("TABLE");
    } else {
      ownerPrivilege.setPrivilegeScope("DATABASE");
    }
    if(ownerPrivilegeType == SentryOwnerPrivilegeType.ALL_WITH_GRANT) {
      ownerPrivilege.setGrantOption(TSentryGrantOption.TRUE);
    }
    ownerPrivilege.setAction(AccessConstants.OWNER);
    return ownerPrivilege;
  }

  /**
   *
   * @param ownerType
   * @return SentryPrincipalType if input was valid, otherwise returns null
   * @throws Exception
   */
  private SentryPrincipalType getSentryPrincipalType(TSentryPrincipalType ownerType) throws Exception {
    return mapOwnerType.get(ownerType);
  }

  /**
   * Syncronizes with the eventId processed by sentry
   * @param eventId
   * @return current counter value that should be no smaller then the requested
   * value, returns 0 if there were an exception.
   */
  long syncEventId(long eventId) {
    try {
        if (!SentryStateBank.isEnabled(FullUpdateInitializerState.COMPONENT,
            FullUpdateInitializerState.FULL_SNAPSHOT_INPROGRESS)) {
          return sentryStore.getCounterWait().waitFor(eventId);
        } else {
          LOGGER.info("HMS event synchronization is disabled temporarily as sentry is in the process of " +
                  "fetching full snapshot. No action needed");
          return eventId;
        }
    } catch (InterruptedException e) {
      String msg = String.format("wait request for id %d is interrupted",
              eventId);
      LOGGER.error(msg, e);
      Thread.currentThread().interrupt();
    } catch (TimeoutException e) {
      String msg = String.format("timed out wait request for id %d", eventId);
      LOGGER.warn(msg, e);
    }
    return 0;
  }
}
