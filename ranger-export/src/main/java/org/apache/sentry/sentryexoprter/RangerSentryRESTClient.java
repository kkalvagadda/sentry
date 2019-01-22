/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sentry.sentryexoprter;

import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.GenericType;
import com.sun.jersey.api.client.WebResource;

import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.security.AccessControlException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.admin.client.RangerAdminClient;
import org.apache.ranger.admin.client.datatype.RESTResponse;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.authorization.utils.StringUtil;
import org.apache.ranger.plugin.util.GrantRevokeRequest;
import org.apache.ranger.plugin.util.RangerRESTClient;
import org.apache.ranger.plugin.util.RangerRESTUtils;
import org.apache.ranger.plugin.util.RangerServiceNotFoundException;
import org.apache.ranger.plugin.util.ServicePolicies;
import org.apache.ranger.plugin.util.ServiceTags;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.apache.sentry.api.service.thrift.TPrivilege;
import org.apache.sentry.api.service.thrift.TSentryPrincipal;
import org.apache.sentry.api.service.thrift.TSentryPrincipalType;

import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.security.PrivilegedAction;
import java.util.*;

public class RangerSentryRESTClient implements RangerAdminClient {
  private static final Log LOG = LogFactory.getLog(RangerSentryRESTClient.class);

  private String           serviceName;
  private String           pluginId;
  private String clusterName;
  private RangerRESTClient restClient;
  private RangerRESTUtils restUtils   = new RangerRESTUtils();

  public static <T> GenericType<List<T>> getGenericType(final T clazz) {

    ParameterizedType parameterizedGenericType = new ParameterizedType() {
      public Type[] getActualTypeArguments() {
        return new Type[] { clazz.getClass() };
      }

      public Type getRawType() {
        return List.class;
      }

      public Type getOwnerType() {
        return List.class;
      }
    };

    return new GenericType<List<T>>(parameterizedGenericType) {};
  }

  @Override
  public void init(String serviceName, String appId, String propertyPrefix) {
    this.serviceName = serviceName;
    this.pluginId    = restUtils.getPluginId(serviceName, appId);

    String url                      = "";
    String tmpUrl                   = RangerConfiguration.getInstance().get(propertyPrefix + ".policy.rest.url");
    String sslConfigFileName 		= RangerConfiguration.getInstance().get(propertyPrefix + ".policy.rest.ssl.config.file");
    clusterName       				= RangerConfiguration.getInstance().get(propertyPrefix + ".ambari.cluster.name", "");
    int	 restClientConnTimeOutMs	= RangerConfiguration.getInstance().getInt(propertyPrefix + ".policy.rest.client.connection.timeoutMs", 120 * 1000);
    int	 restClientReadTimeOutMs	= RangerConfiguration.getInstance().getInt(propertyPrefix + ".policy.rest.client.read.timeoutMs", 30 * 1000);
    if (!StringUtil.isEmpty(tmpUrl)) {
      url = tmpUrl.trim();
    }
    if (url.endsWith("/")) {
      url = url.substring(0, url.length() - 1);
    }

    init(url, sslConfigFileName, restClientConnTimeOutMs , restClientReadTimeOutMs);
  }

  @Override
  public ServicePolicies getServicePoliciesIfUpdated(final long lastKnownVersion, final long lastActivationTimeInMillis) throws Exception {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerAdminRESTClient.getServicePoliciesIfUpdated(" + lastKnownVersion + ", " + lastActivationTimeInMillis + ")");
    }

    ServicePolicies ret = null;
    UserGroupInformation user = MiscUtil.getUGILoginUser();
    boolean isSecureMode = user != null && UserGroupInformation.isSecurityEnabled();
    ClientResponse response = null;
    if (isSecureMode) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Checking Service policy if updated as user : " + user);
      }
      PrivilegedAction<ClientResponse> action = new PrivilegedAction<ClientResponse>() {
        public ClientResponse run() {
          WebResource secureWebResource = createWebResource(RangerRESTUtils.REST_URL_POLICY_GET_FOR_SECURE_SERVICE_IF_UPDATED + serviceName)
                  .queryParam(RangerRESTUtils.REST_PARAM_LAST_KNOWN_POLICY_VERSION, Long.toString(lastKnownVersion))
                  .queryParam(RangerRESTUtils.REST_PARAM_LAST_ACTIVATION_TIME, Long.toString(lastActivationTimeInMillis))
                  .queryParam(RangerRESTUtils.REST_PARAM_PLUGIN_ID, pluginId)
                  .queryParam(RangerRESTUtils.REST_PARAM_CLUSTER_NAME, clusterName);
          return secureWebResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
        }
      };
      response = user.doAs(action);
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Checking Service policy if updated with old api call");
      }
      WebResource webResource = createWebResource(RangerRESTUtils.REST_URL_POLICY_GET_FOR_SERVICE_IF_UPDATED + serviceName)
              .queryParam(RangerRESTUtils.REST_PARAM_LAST_KNOWN_POLICY_VERSION, Long.toString(lastKnownVersion))
              .queryParam(RangerRESTUtils.REST_PARAM_LAST_ACTIVATION_TIME, Long.toString(lastActivationTimeInMillis))
              .queryParam(RangerRESTUtils.REST_PARAM_PLUGIN_ID, pluginId)
              .queryParam(RangerRESTUtils.REST_PARAM_CLUSTER_NAME, clusterName);
      response = webResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
    }

    if (response == null || response.getStatus() == HttpServletResponse.SC_NOT_MODIFIED) {
      if (response == null) {
        LOG.error("Error getting policies; Received NULL response!!. secureMode=" + isSecureMode + ", user=" + user + ", serviceName=" + serviceName);
      } else {
        RESTResponse resp = RESTResponse.fromClientResponse(response);
        if (LOG.isDebugEnabled()) {
          LOG.debug("No change in policies. secureMode=" + isSecureMode + ", user=" + user + ", response=" + resp + ", serviceName=" + serviceName);
        }
      }
      ret = null;
    } else if (response.getStatus() == HttpServletResponse.SC_OK) {
      ret = response.getEntity(ServicePolicies.class);
    } else if (response.getStatus() == HttpServletResponse.SC_NOT_FOUND) {
      LOG.error("Error getting policies; service not found. secureMode=" + isSecureMode + ", user=" + user
              + ", response=" + response.getStatus() + ", serviceName=" + serviceName
              + ", " + "lastKnownVersion=" + lastKnownVersion
              + ", " + "lastActivationTimeInMillis=" + lastActivationTimeInMillis);
      String exceptionMsg = response.hasEntity() ? response.getEntity(String.class) : null;

      RangerServiceNotFoundException.throwExceptionIfServiceNotFound(serviceName, exceptionMsg);

      LOG.warn("Received 404 error code with body:[" + exceptionMsg + "], Ignoring");
    } else {
      RESTResponse resp = RESTResponse.fromClientResponse(response);
      LOG.warn("Error getting policies. secureMode=" + isSecureMode + ", user=" + user + ", response=" + resp + ", serviceName=" + serviceName);
      ret = null;
    }

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== RangerAdminRESTClient.getServicePoliciesIfUpdated(" + lastKnownVersion + ", " + lastActivationTimeInMillis + "): " + ret);
    }

    return ret;
  }

  public long ingestPolicy(RangerResource resource, Map<TSentryPrincipal, List<TPrivilege>> permissions) throws Exception {
    Random random = new Random();
    RangerPolicy policyCreated = null;
    ClientResponse response = null;
    UserGroupInformation user = MiscUtil.getUGILoginUser();
    boolean isSecureMode = user != null && UserGroupInformation.isSecurityEnabled();
    WebResource webResource = null;
    // create policy ( working)
    webResource = createWebResource("/service/plugins/policies");
    webResource.addFilter(new HTTPBasicAuthFilter("admin", "hortonworks1"));
    if(resource == null) {
      //TODO Handle this case.
      return 0L;
    }
    Map<String, RangerPolicy.RangerPolicyResource> resources = new HashMap<>();
    String policyName = null;
    RangerPolicy.RangerPolicyItem rangerPolicyItem;
    switch (resource.getObjectType()) {
      case DATABASE:
        resources.put("database", new RangerPolicy.RangerPolicyResource(resource.getDatabase()));
        resources.put("table", new RangerPolicy.RangerPolicyResource("*"));
        resources.put("column", new RangerPolicy.RangerPolicyResource("*"));
        policyName = "database" + "=" + resource.getDatabase();
        break;
      case COLUMN:
        resources.put("database", new RangerPolicy.RangerPolicyResource(resource.getDatabase()));
        resources.put("table", new RangerPolicy.RangerPolicyResource(resource.getTable()));
        resources.put("column", new RangerPolicy.RangerPolicyResource(resource.getColumn()));
        policyName = "database" + "=" + resource.getDatabase() + "->" + "table" + "=" + resource.getTable()
                + "->" + "column" + "=" + resource.getColumn();
        break;
      case TABLE:
      case VIEW:
      case INDEX:
      case PARTITION:
        resources.put("database", new RangerPolicy.RangerPolicyResource(resource.getDatabase()));
        resources.put("table", new RangerPolicy.RangerPolicyResource(resource.getTable()));
        resources.put("column", new RangerPolicy.RangerPolicyResource("*"));
        policyName = "database" + "=" + resource.getDatabase() + "->" + "table" + "=" + resource.getTable();
        break;
      case URI:
        //TODO
//          resources.put("database", new RangerPolicy.RangerPolicyResource(resource.getDatabase()));
//          resources.put("table", new RangerPolicy.RangerPolicyResource(resource.getTable()));
        break;
      case NONE:
      default:
        break;
    }
    RangerPolicy policy = new RangerPolicy();
    policy.setService("Sandbox_hive");
    policy.setName(String.valueOf(random.nextInt(Integer.MAX_VALUE - 1)));
    policy.setName(policyName);
    policy.setDescription("created by kalyan");
    policy.setIsAuditEnabled(true);
    policy.setCreatedBy("admin");
    policy.setResources(resources);
    policy.setPolicyLabels(Collections.singletonList("Ingested from Sentry"));

    for (Map.Entry<TSentryPrincipal, List<TPrivilege>> permission : permissions.entrySet()) {
      rangerPolicyItem = new RangerPolicy.RangerPolicyItem();
      for (TPrivilege privilege : permission.getValue()) {
        if(privilege.getAction().equals("*") || privilege.getAction().equals("owner")) {
          privilege.setAction("all");
        }
        if(privilege.getAction().equals("owner")) {
          privilege.setAction("all");
        }
        rangerPolicyItem.getAccesses().add(new RangerPolicy.RangerPolicyItemAccess(privilege.getAction(), true));
      }
      if (permission.getKey().getType() == TSentryPrincipalType.GROUP) {
        rangerPolicyItem.getGroups().add(permission.getKey().getName());
      } else if (permission.getKey().getType() == TSentryPrincipalType.USER) {
        rangerPolicyItem.getUsers().add(permission.getKey().getName());
      } else {
        throw new Exception("Invalid Principal Type");
      }
      rangerPolicyItem.setDelegateAdmin(false);
      policy.getPolicyItems().add(rangerPolicyItem);
    }

    response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE)
            .post(ClientResponse.class,
                    restClient.toJson(policy));

    if (response != null && response.getStatus() != HttpServletResponse.SC_OK) {
      RESTResponse resp = RESTResponse.fromClientResponse(response);
      LOG.error("grantAccess() failed: HTTP status=" + response.getStatus() + ", message=" + resp.getMessage() + ", isSecure=" + isSecureMode + (isSecureMode ? (", user=" + user) : ""));

      if (response.getStatus() == HttpServletResponse.SC_UNAUTHORIZED) {
        throw new AccessControlException();
      }

      throw new Exception("HTTP " + response.getStatus() + " Error: " + resp.getMessage());
    } else if (response == null) {
      throw new Exception("unknown error during grantAccess. serviceName=" + serviceName);
    } else if (response.getStatus() == HttpServletResponse.SC_OK) {
      // RESTResponse resp = RESTResponse.fromClientResponse(response);
      policyCreated = response.getEntity(RangerPolicy.class);
      LOG.error("Policy is created with id %s" + policyCreated.getId());
      Thread.sleep(1000);
    }
    if(policyCreated != null) {
      return policyCreated.getId();
    } else {
      throw new Exception("Ingestion failed");
    }
  }

  @Override
  public void grantAccess(final GrantRevokeRequest request) throws Exception {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerAdminRESTClient.grantAccess(" + request + ")");
    }

    ClientResponse response = null;
    UserGroupInformation user = MiscUtil.getUGILoginUser();
    boolean isSecureMode = user != null && UserGroupInformation.isSecurityEnabled();

    if (isSecureMode) {
      PrivilegedAction<ClientResponse> action = new PrivilegedAction<ClientResponse>() {
        public ClientResponse run() {
          WebResource secureWebResource = createWebResource(RangerRESTUtils.REST_URL_SECURE_SERVICE_GRANT_ACCESS + serviceName);
          return secureWebResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).post(ClientResponse.class, restClient.toJson(request));
        }
      };
      if (LOG.isDebugEnabled()) {
        LOG.debug("grantAccess as user " + user);
      }
      response = user.doAs(action);
    } else {
      //exporting

//      WebResource webResource = createWebResource("/service/plugins/policies/exportJson")
//              .queryParam("serviceName", "Sandbox_hive")
//              .queryParam("checkPoliciesExists", "false");
//      webResource.addFilter(new HTTPBasicAuthFilter("admin", "hortonworks1"));
//      response = webResource.accept("text/json,application/xhtml+xml,application/xml").get(ClientResponse.class);

      // Grant privilege
//      WebResource webResource = createWebResource("/service/plugins/services/grant/"+ serviceName);
//      webResource.addFilter(new HTTPBasicAuthFilter("admin", "hortonworks1"));
//      response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).post(ClientResponse.class, restClient.toJson(request));


      // Update ranger policy
//      WebResource webResource = createWebResource("/service/plugins/policies/17");
//      webResource.addFilter(new HTTPBasicAuthFilter("admin", "hortonworks1"));
// //     RangerPolicy policy = new RangerPolicy("Sandbox_hive", "temp", 0, 0, "", )
//      response = webResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).type(RangerRESTUtils.REST_MIME_TYPE_JSON).put(ClientResponse.class,
//              restClient.toJson(new RangerPolicy()));

//       create policy ( working)
//            WebResource webResource = createWebResource("/service/plugins/policies");
//      webResource.addFilter(new HTTPBasicAuthFilter("admin", "hortonworks1"));
//      Map<String, RangerPolicy.RangerPolicyResource> resources = new HashMap<>();
//      resources.put("database", new RangerPolicy.RangerPolicyResource("database1"));
//      resources.put("table", new RangerPolicy.RangerPolicyResource("table1"));
//      resources.put("column", new RangerPolicy.RangerPolicyResource("column1"));
//      RangerPolicy.RangerPolicyItem rangerPolicyItem = new RangerPolicy.RangerPolicyItem();
//      rangerPolicyItem.getAccesses().add(new RangerPolicy.RangerPolicyItemAccess("create", true));
//      rangerPolicyItem.getGroups().add("raj_ops");
//      rangerPolicyItem.getUsers().add("raj_ops");
//      rangerPolicyItem.getUsers().add("kafka");
//      rangerPolicyItem.setDelegateAdmin(false);
//      RangerPolicy policy = new RangerPolicy();
//      policy.setService("Sandbox_hive");
//      policy.setName("temp1234");
//      policy.setDescription("created by kalyan");
//      policy.setIsAuditEnabled(false);
//      policy.setCreatedBy("admin");
//      policy.setResources(resources);
//      policy.getPolicyItems().add(rangerPolicyItem);
//
//      response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE)
//              .post(ClientResponse.class,
//              restClient.toJson(policy));

      // Delete policy ( working)
      WebResource webResource = createWebResource("/service/plugins/policies/28");
      webResource.addFilter(new HTTPBasicAuthFilter("admin", "hortonworks1"));
      response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE)
              .delete(ClientResponse.class);

      response = webResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).type(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
      response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).get(ClientResponse.class);

    }
    if(response != null && response.getStatus() != HttpServletResponse.SC_OK) {
      RESTResponse resp = RESTResponse.fromClientResponse(response);
      LOG.error("grantAccess() failed: HTTP status=" + response.getStatus() + ", message=" + resp.getMessage() + ", isSecure=" + isSecureMode + (isSecureMode ? (", user=" + user) : ""));

      if(response.getStatus()==HttpServletResponse.SC_UNAUTHORIZED) {
        throw new AccessControlException();
      }

      throw new Exception("HTTP " + response.getStatus() + " Error: " + resp.getMessage());
    } else if(response == null) {
      throw new Exception("unknown error during grantAccess. serviceName="  + serviceName);
    } else if (response.getStatus() == HttpServletResponse.SC_OK) {
      // RESTResponse resp = RESTResponse.fromClientResponse(response);
      RangerPolicy policyCreated = response.getEntity(RangerPolicy.class);
      LOG.error("Policy is created with id %s" + policyCreated.getId());
    }

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== RangerAdminRESTClient.grantAccess(" + request + ")");
    }
  }

  public void revokeAccess(List<Long> policyIds) throws Exception {
    //  Delete policy ( working)
    ClientResponse response = null;
    for(long id : policyIds) {
      WebResource webResource = createWebResource("/service/plugins/policies/" + id);
      webResource.addFilter(new HTTPBasicAuthFilter("admin", "hortonworks1"));
      response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).accept("*/*")
              .delete(ClientResponse.class);

//      response = webResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).type(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
      //   response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).get(ClientResponse.class);

      if (response != null && !(response.getStatus() >= 200 && response.getStatus() < 300)) {
        RESTResponse resp = RESTResponse.fromClientResponse(response);
        LOG.error("revokeAccess() failed: HTTP status=" + response.getStatus() + ", message=" + resp.getMessage());

        if (response.getStatus() == HttpServletResponse.SC_UNAUTHORIZED) {
          throw new AccessControlException();
        }

       // throw new Exception("HTTP " + response.getStatus() + " Error: " + resp.getMessage());
          continue;
      } else if (response == null) {
        throw new Exception("unknown error during revokeAccess. serviceName=" + serviceName);
      } else if (response.getStatus() == HttpServletResponse.SC_OK || response.getStatus() == HttpServletResponse.SC_NO_CONTENT) {
        LOG.error("Policy with id %s revoked" + id);
        System.out.println("Policy with id: " + id + " revoked");
      }
    }
  }
  @Override
  public void revokeAccess(final GrantRevokeRequest request) throws Exception {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerAdminRESTClient.revokeAccess(" + request + ")");
    }

    ClientResponse response = null;
    UserGroupInformation user = MiscUtil.getUGILoginUser();
    boolean isSecureMode = user != null && UserGroupInformation.isSecurityEnabled();

    if (isSecureMode) {
      PrivilegedAction<ClientResponse> action = new PrivilegedAction<ClientResponse>() {
        public ClientResponse run() {
          WebResource secureWebResource = createWebResource(RangerRESTUtils.REST_URL_SECURE_SERVICE_REVOKE_ACCESS + serviceName)
                  .queryParam(RangerRESTUtils.REST_PARAM_PLUGIN_ID, pluginId);
          return secureWebResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).post(ClientResponse.class, restClient.toJson(request));
        }
      };
      if (LOG.isDebugEnabled()) {
        LOG.debug("revokeAccess as user " + user);
      }
      response = user.doAs(action);
    } else {
      WebResource webResource = createWebResource(RangerRESTUtils.REST_URL_SERVICE_REVOKE_ACCESS + serviceName)
              .queryParam(RangerRESTUtils.REST_PARAM_PLUGIN_ID, pluginId);
      response = webResource.accept(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).type(RangerRESTUtils.REST_EXPECTED_MIME_TYPE).post(ClientResponse.class, restClient.toJson(request));
    }

    if(response != null && response.getStatus() != HttpServletResponse.SC_OK) {
      RESTResponse resp = RESTResponse.fromClientResponse(response);
      LOG.error("revokeAccess() failed: HTTP status=" + response.getStatus() + ", message=" + resp.getMessage() + ", isSecure=" + isSecureMode + (isSecureMode ? (", user=" + user) : ""));

      if(response.getStatus() == HttpServletResponse.SC_UNAUTHORIZED) {
        throw new AccessControlException();
      }

      throw new Exception("HTTP " + response.getStatus() + " Error: " + resp.getMessage());
    } else if(response == null) {
      throw new Exception("unknown error. revokeAccess(). serviceName=" + serviceName);
    }

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== RangerAdminRESTClient.revokeAccess(" + request + ")");
    }
  }

  private void init(String url, String sslConfigFileName, int restClientConnTimeOutMs , int restClientReadTimeOutMs ) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerAdminRESTClient.init(" + url + ", " + sslConfigFileName + ")");
    }

    restClient = new RangerRESTClient(url, sslConfigFileName);
    restClient.setRestClientConnTimeOutMs(restClientConnTimeOutMs);
    restClient.setRestClientReadTimeOutMs(restClientReadTimeOutMs);

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== RangerAdminRESTClient.init(" + url + ", " + sslConfigFileName + ")");
    }
  }

  private WebResource createWebResource(String url) {
    WebResource ret = restClient.getResource(url);

    return ret;
  }

  @Override
  public ServiceTags getServiceTagsIfUpdated(final long lastKnownVersion, final long lastActivationTimeInMillis) throws Exception {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerAdminRESTClient.getServiceTagsIfUpdated(" + lastKnownVersion + ", " + lastActivationTimeInMillis + "): ");
    }

    ServiceTags ret = null;
    ClientResponse response = null;
    WebResource webResource = null;
    UserGroupInformation user = MiscUtil.getUGILoginUser();
    boolean isSecureMode = user != null && UserGroupInformation.isSecurityEnabled();

    if (isSecureMode) {
      PrivilegedAction<ClientResponse> action = new PrivilegedAction<ClientResponse>() {
        public ClientResponse run() {
          WebResource secureWebResource = createWebResource(RangerRESTUtils.REST_URL_GET_SECURE_SERVICE_TAGS_IF_UPDATED + serviceName)
                  .queryParam(RangerRESTUtils.LAST_KNOWN_TAG_VERSION_PARAM, Long.toString(lastKnownVersion))
                  .queryParam(RangerRESTUtils.REST_PARAM_LAST_ACTIVATION_TIME, Long.toString(lastActivationTimeInMillis))
                  .queryParam(RangerRESTUtils.REST_PARAM_PLUGIN_ID, pluginId);
          return secureWebResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
        }
      };
      if (LOG.isDebugEnabled()) {
        LOG.debug("getServiceTagsIfUpdated as user " + user);
      }
      response = user.doAs(action);
    } else {
      webResource = createWebResource(RangerRESTUtils.REST_URL_GET_SERVICE_TAGS_IF_UPDATED + serviceName)
              .queryParam(RangerRESTUtils.LAST_KNOWN_TAG_VERSION_PARAM, Long.toString(lastKnownVersion))
              .queryParam(RangerRESTUtils.REST_PARAM_LAST_ACTIVATION_TIME, Long.toString(lastActivationTimeInMillis))
              .queryParam(RangerRESTUtils.REST_PARAM_PLUGIN_ID, pluginId);
      response = webResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
    }

    if (response == null || response.getStatus() == HttpServletResponse.SC_NOT_MODIFIED) {
      if (response == null) {
        LOG.error("Error getting tags; Received NULL response!!. secureMode=" + isSecureMode + ", user=" + user + ", serviceName=" + serviceName);
      } else {
        RESTResponse resp = RESTResponse.fromClientResponse(response);
        if (LOG.isDebugEnabled()) {
          LOG.debug("No change in tags. secureMode=" + isSecureMode + ", user=" + user
                  + ", response=" + resp + ", serviceName=" + serviceName
                  + ", " + "lastKnownVersion=" + lastKnownVersion
                  + ", " + "lastActivationTimeInMillis=" + lastActivationTimeInMillis);
        }
      }
      ret = null;
    } else if (response.getStatus() == HttpServletResponse.SC_OK) {
      ret = response.getEntity(ServiceTags.class);
    } else if (response.getStatus() == HttpServletResponse.SC_NOT_FOUND) {
      LOG.error("Error getting tags; service not found. secureMode=" + isSecureMode + ", user=" + user
              + ", response=" + response.getStatus() + ", serviceName=" + serviceName
              + ", " + "lastKnownVersion=" + lastKnownVersion
              + ", " + "lastActivationTimeInMillis=" + lastActivationTimeInMillis);
      String exceptionMsg = response.hasEntity() ? response.getEntity(String.class) : null;

      RangerServiceNotFoundException.throwExceptionIfServiceNotFound(serviceName, exceptionMsg);

      LOG.warn("Received 404 error code with body:[" + exceptionMsg + "], Ignoring");
    } else {
      RESTResponse resp = RESTResponse.fromClientResponse(response);
      LOG.warn("Error getting tags. secureMode=" + isSecureMode + ", user=" + user + ", response=" + resp + ", serviceName=" + serviceName);
      ret = null;
    }

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== RangerAdminRESTClient.getServiceTagsIfUpdated(" + lastKnownVersion + ", " + lastActivationTimeInMillis + "): ");
    }

    return ret;
  }

  @Override
  public List<String> getTagTypes(String pattern) throws Exception {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerAdminRESTClient.getTagTypes(" + pattern + "): ");
    }

    List<String> ret = null;
    String emptyString = "";
    UserGroupInformation user = MiscUtil.getUGILoginUser();
    boolean isSecureMode = user != null && UserGroupInformation.isSecurityEnabled();

    final WebResource webResource = createWebResource(RangerRESTUtils.REST_URL_LOOKUP_TAG_NAMES)
            .queryParam(RangerRESTUtils.SERVICE_NAME_PARAM, serviceName)
            .queryParam(RangerRESTUtils.PATTERN_PARAM, pattern);

    ClientResponse response = null;
    if (isSecureMode) {
      PrivilegedAction<ClientResponse> action = new PrivilegedAction<ClientResponse>() {
        public ClientResponse run() {
          return webResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
        }
      };
      if (LOG.isDebugEnabled()) {
        LOG.debug("getTagTypes as user " + user);
      }
      response = user.doAs(action);
    } else {
      response = webResource.accept(RangerRESTUtils.REST_MIME_TYPE_JSON).get(ClientResponse.class);
    }

    if(response != null && response.getStatus() == HttpServletResponse.SC_OK) {
      ret = response.getEntity(getGenericType(emptyString));
    } else {
      RESTResponse resp = RESTResponse.fromClientResponse(response);
      LOG.error("Error getting tags. request=" + webResource
              + ", response=" + resp + ", serviceName=" + serviceName
              + ", " + "pattern=" + pattern);
      throw new Exception(resp.getMessage());
    }

    if(LOG.isDebugEnabled()) {
      LOG.debug("<== RangerAdminRESTClient.getTagTypes(" + pattern + "): " + ret);
    }

    return ret;
  }

}

