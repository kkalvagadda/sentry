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

import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.hive.ql.security.authorization.plugin.*;
import org.apache.ranger.admin.client.RangerAdminClient;
import org.apache.ranger.admin.client.RangerAdminRESTClient;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.authorization.hive.authorizer.RangerHiveResource;
import org.apache.ranger.authorization.utils.StringUtil;
import org.apache.ranger.plugin.util.GrantRevokeRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SentryExporter {
  enum HiveAccessType { NONE, CREATE, ALTER, DROP, INDEX, LOCK, SELECT, UPDATE, USE, READ, WRITE, ALL, ADMIN };
  public static void main(String[] args) throws Exception {
    System.out.println("Test");

    // Initialize

    RangerConfiguration configuration = RangerConfiguration.getInstance();
    configuration.addResourcesForServiceType("hive");
    String propertyPrefix    = "ranger.plugin." + "hive";

    String serviceName = configuration.get(propertyPrefix + ".service.name");



    // Create ranger client
    RangerAdminClient client = createAdminClient(serviceName, "hive", propertyPrefix);
    // Try to connect to server

    // Construct grant request
    HivePrivilegeObject hivePrivObject = new HivePrivilegeObject(HivePrivilegeObject.HivePrivilegeObjectType.TABLE_OR_VIEW,
            "testing", "test");
    RangerResource resource = getHiveResource(HiveOperationType.GRANT_PRIVILEGE, hivePrivObject);

    GrantRevokeRequest grantRequest = createGrantRevokeData(resource,
            Collections.singletonList(new HivePrincipal("kkalyan", HivePrincipal.HivePrincipalType.USER)),
            Collections.singletonList(new HivePrivilege("SELECT", null)), false);
    // Send a request to server
    client.grantAccess(grantRequest);
  }

  private static final Log LOG = LogFactory.getLog(SentryExporter.class);

  private static RangerAdminClient createAdminClient(String rangerServiceName, String applicationId, String propertyPrefix) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerBasePlugin.createAdminClient(" + rangerServiceName + ", " + applicationId + ", " + propertyPrefix + ")");
    }

    RangerAdminClient ret = null;

    String propertyName = propertyPrefix + ".policy.source.impl";
    String policySourceImpl = RangerConfiguration.getInstance().get(propertyName);

    if(StringUtils.isEmpty(policySourceImpl)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(String.format("Value for property[%s] was null or empty. Unexpected! Will use policy source of type[%s]", propertyName, RangerAdminRESTClient.class.getName()));
      }
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug(String.format("Value for property[%s] was [%s].", propertyName, policySourceImpl));
      }
      try {
        @SuppressWarnings("unchecked")
        Class<RangerAdminClient> adminClass = (Class<RangerAdminClient>)Class.forName(policySourceImpl);

        ret = adminClass.newInstance();
      } catch (Exception excp) {
        LOG.error("failed to instantiate policy source of type '" + policySourceImpl + "'. Will use policy source of type '" + RangerAdminRESTClient.class.getName() + "'", excp);
      }
    }

    if(ret == null) {
      ret = new RangerAdminRESTClient();
    }

    ret.init(rangerServiceName, applicationId, propertyPrefix);

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== RangerBasePlugin.createAdminClient(" + rangerServiceName + ", " + applicationId + ", " + propertyPrefix + "): policySourceImpl=" + policySourceImpl + ", client=" + ret);
    }
    return ret;
  }

  private static RangerResource getHiveResource(HiveOperationType   hiveOpType,
                                             HivePrivilegeObject hiveObj) {
    RangerResource ret = null;

    ServiceConstants.HiveObjectType objectType = getObjectType(hiveObj, hiveOpType);
    switch(objectType) {
      case DATABASE:
        ret = new RangerResource(objectType, hiveObj.getDbname());
        break;

      case TABLE:
      case VIEW:
      case PARTITION:
      case INDEX:
      case FUNCTION:
        ret = new RangerResource(objectType, hiveObj.getDbname(), hiveObj.getObjectName());
        break;

      case COLUMN:
        ret = new RangerResource(objectType, hiveObj.getDbname(), hiveObj.getObjectName(), StringUtils.join(hiveObj.getColumns(), ","));
        break;

      case URI:
        ret = new RangerResource(objectType, hiveObj.getObjectName());
        break;

      case NONE:
        break;
    }
    return ret;
  }


  private static ServiceConstants.HiveObjectType getObjectType(HivePrivilegeObject hiveObj, HiveOperationType hiveOpType) {
    ServiceConstants.HiveObjectType objType = ServiceConstants.HiveObjectType.NONE;
    if (hiveObj.getType() == null) {
      return ServiceConstants.HiveObjectType.DATABASE;
    }

    switch(hiveObj.getType()) {
      case DATABASE:
        objType = ServiceConstants.HiveObjectType.DATABASE;
        break;

      case PARTITION:
        objType = ServiceConstants.HiveObjectType.PARTITION;
        break;

      case TABLE_OR_VIEW:
        String hiveOpTypeName = hiveOpType.name().toLowerCase();
        if(hiveOpTypeName.contains("index")) {
          objType = ServiceConstants.HiveObjectType.INDEX;
        } else if(! StringUtil.isEmpty(hiveObj.getColumns())) {
          objType = ServiceConstants.HiveObjectType.COLUMN;
        } else if(hiveOpTypeName.contains("view")) {
          objType = ServiceConstants.HiveObjectType.VIEW;
        } else {
          objType = ServiceConstants.HiveObjectType.TABLE;
        }
        break;

      case FUNCTION:
        objType = ServiceConstants.HiveObjectType.FUNCTION;
        break;

      case DFS_URI:
      case LOCAL_URI:
        objType = ServiceConstants.HiveObjectType.URI;
        break;

      case COMMAND_PARAMS:
      case GLOBAL:
        break;

      case COLUMN:
        // Thejas: this value is unused in Hive; the case should not be hit.
        break;
    }

    return objType;
  }

  private static GrantRevokeRequest createGrantRevokeData(RangerResource resource,
                                                   List<HivePrincipal> hivePrincipals,
                                                   List<HivePrivilege> hivePrivileges,
                                                   boolean             grantOption)
          throws HiveAccessControlException {

    GrantRevokeRequest ret = new GrantRevokeRequest();

    ret.setGrantor("rangeradmin");
    ret.setGrantorGroups(Collections.singleton("admin"));
    ret.setDelegateAdmin(grantOption ? Boolean.TRUE : Boolean.FALSE);
    ret.setEnableAudit(Boolean.TRUE);
    ret.setReplaceExistingPermissions(Boolean.FALSE);

    String database = StringUtils.isEmpty(resource.getDatabase()) ? "*" : resource.getDatabase();
    String table    = StringUtils.isEmpty(resource.getTable()) ? "*" : resource.getTable();
    String column   = StringUtils.isEmpty(resource.getColumn()) ? "*" : resource.getColumn();

    Map<String, String> mapResource = new HashMap<String, String>();
    mapResource.put(RangerHiveResource.KEY_DATABASE, database);
    mapResource.put(RangerHiveResource.KEY_TABLE, table);
    mapResource.put(RangerHiveResource.KEY_COLUMN, column);

    ret.setResource(mapResource);

    for(HivePrincipal principal : hivePrincipals) {
      switch(principal.getType()) {
        case USER:
          ret.getUsers().add(principal.getName());
          break;

        case GROUP:
        case ROLE:
          ret.getGroups().add(principal.getName());
          break;

        case UNKNOWN:
          break;
      }
    }

    for(HivePrivilege privilege : hivePrivileges) {
      String privName = privilege.getName();

      if(StringUtils.equalsIgnoreCase(privName, HiveAccessType.ALL.name()) ||
              StringUtils.equalsIgnoreCase(privName, HiveAccessType.ALTER.name()) ||
              StringUtils.equalsIgnoreCase(privName, HiveAccessType.CREATE.name()) ||
              StringUtils.equalsIgnoreCase(privName, HiveAccessType.DROP.name()) ||
              StringUtils.equalsIgnoreCase(privName, HiveAccessType.INDEX.name()) ||
              StringUtils.equalsIgnoreCase(privName, HiveAccessType.LOCK.name()) ||
              StringUtils.equalsIgnoreCase(privName, HiveAccessType.SELECT.name()) ||
              StringUtils.equalsIgnoreCase(privName, HiveAccessType.UPDATE.name())) {
        ret.getAccessTypes().add(privName.toLowerCase());
      } else if (StringUtils.equalsIgnoreCase(privName, "Insert") ||
              StringUtils.equalsIgnoreCase(privName, "Delete")) {
        // Mapping Insert/Delete to Update
        ret.getAccessTypes().add(HiveAccessType.UPDATE.name().toLowerCase());
      } else {
        LOG.warn("grant/revoke: unexpected privilege type '" + privName + "'. Ignored");
      }
    }
    return ret;
  }
}
