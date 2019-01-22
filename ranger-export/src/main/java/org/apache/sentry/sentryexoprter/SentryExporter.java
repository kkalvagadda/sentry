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


import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.cli.*;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hive.ql.security.authorization.plugin.*;
import org.apache.ranger.admin.client.RangerAdminRESTClient;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.authorization.hive.authorizer.RangerHiveResource;
import org.apache.ranger.authorization.utils.StringUtil;
import org.apache.ranger.plugin.util.GrantRevokeRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.sentry.api.service.thrift.*;
import org.apache.sentry.service.thrift.SentryServiceClientFactory;


import java.io.FileWriter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class SentryExporter {
    enum HiveAccessType {NONE, CREATE, ALTER, DROP, INDEX, LOCK, SELECT, UPDATE, USE, READ, WRITE, ALL, ADMIN}

    ;
    boolean doMigration = false;
    String sentryConfig;
    String rangerConfig;
    RangerSentryRESTClient rangerClient = null;
    SentryPolicyServiceClient client = null;


    String rangerServiceName, applicationId, servicePropertyPrefix;
    SentryExporter() {

    }

    SentryExporter(String[] args) throws Exception {
        parseArgs(args);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Test");

        SentryExporter exporter = new SentryExporter();

        exporter.parseArgs(args);

        exporter.execute();
    }

    private static final Log LOG = LogFactory.getLog(SentryExporter.class);

    private Configuration getSentryConf() {
        Configuration conf = new Configuration();
        conf.addResource(new Path(sentryConfig), true);
        return conf;
    }

    private void setup() throws Exception {
        RangerConfiguration configuration = RangerConfiguration.getInstance();
        configuration.addResourcesForServiceType("hive");
        String propertyPrefix = "ranger.plugin." + "hive";

        String serviceName = configuration.get(propertyPrefix + ".service.name");

        Configuration conf = getSentryConf();
        conf.reloadConfiguration();

        // initialize ranger client
        rangerClient = createAdminClient(serviceName, "hive", propertyPrefix);
        rangerServiceName = serviceName;
        applicationId = "hive";
        servicePropertyPrefix = propertyPrefix;

        client = SentryServiceClientFactory.create(conf);
    }

    @VisibleForTesting
    void setSentryConfig(String location) {
        sentryConfig = location;
    }

    @VisibleForTesting
    void setRangerConfig(String location) {
        rangerConfig = location;
    }

    @VisibleForTesting
    void execute() throws Exception {

    //    List<Long> policyIdsIngested = new ArrayList<>();
        String requestorName = "hive";

        // Setting up the ranger and sentry clients.
        setup();

        // Fetch the permission mapping
        Map<TSentryAuthorizable, Map<TSentryPrincipal, List<TPrivilege>>> mapping =
                client.fetchPolicyMappings(requestorName);
        FileWriter writer = new FileWriter("/Users/loanermbp7345/output.txt");
        ExecutorService executorService = Executors.newFixedThreadPool(10);

        for (Map.Entry<TSentryAuthorizable, Map<TSentryPrincipal, List<TPrivilege>>> permissionInfo : mapping.entrySet()) {
            if (permissionInfo.getValue().size() == 0) {
                // TODO This has to be fixed in sentry server.
                continue;
            }
   //         policyIdsIngested.add(policyIdIngested);
            executorService.submit(new RangerExporter(permissionInfo.getKey(), permissionInfo.getValue()));
            writer.write("Exporting permission for " + permissionInfo.getKey().toString());
            writer.write("\r\n");
            writer.flush();
        }
        executorService.shutdown();
        executorService.awaitTermination(1000, TimeUnit.SECONDS);
        writer.close();
    }

    @VisibleForTesting
    void revokePermissions(List<Long> policyIds) throws Exception {
        // Setting up the ranger and sentry clients.
        setup();
        rangerClient.revokeAccess(policyIds);
    }

    private static RangerSentryRESTClient createAdminClient(String rangerServiceName, String applicationId, String propertyPrefix) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("==> RangerBasePlugin.createAdminClient(" + rangerServiceName + ", " + applicationId + ", " + propertyPrefix + ")");
        }

        RangerSentryRESTClient ret = null;

        String propertyName = propertyPrefix + ".policy.source.impl";
        String policySourceImpl = RangerConfiguration.getInstance().get(propertyName);

        if (StringUtils.isEmpty(policySourceImpl)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Value for property[%s] was null or empty. Unexpected! Will use policy source of type[%s]", propertyName, RangerAdminRESTClient.class.getName()));
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Value for property[%s] was [%s].", propertyName, policySourceImpl));
            }
            try {

                ret = RangerSentryRESTClient.class.newInstance();
            } catch (Exception excp) {
                LOG.error("failed to instantiate policy source of type '" + policySourceImpl + "'. Will use policy source of type '" + RangerAdminRESTClient.class.getName() + "'", excp);
            }
        }

        if (ret == null) {
            ret = new RangerSentryRESTClient();
        }

        ret.init(rangerServiceName, applicationId, propertyPrefix);

        if (LOG.isDebugEnabled()) {
            LOG.debug("<== RangerBasePlugin.createAdminClient(" + rangerServiceName + ", " + applicationId + ", " + propertyPrefix + "): policySourceImpl=" + policySourceImpl + ", client=" + ret);
        }
        return ret;
    }

    private static RangerResource getHiveResource(HiveOperationType hiveOpType,
                                                  HivePrivilegeObject hiveObj) {
        RangerResource ret = null;

        ServiceConstants.HiveObjectType objectType = getObjectType(hiveObj, hiveOpType);
        switch (objectType) {
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

        switch (hiveObj.getType()) {
            case DATABASE:
                objType = ServiceConstants.HiveObjectType.DATABASE;
                break;

            case PARTITION:
                objType = ServiceConstants.HiveObjectType.PARTITION;
                break;

            case TABLE_OR_VIEW:
                String hiveOpTypeName = hiveOpType.name().toLowerCase();
                if (hiveOpTypeName.contains("index")) {
                    objType = ServiceConstants.HiveObjectType.INDEX;
                } else if (!StringUtil.isEmpty(hiveObj.getColumns())) {
                    objType = ServiceConstants.HiveObjectType.COLUMN;
                } else if (hiveOpTypeName.contains("view")) {
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

    public static GrantRevokeRequest createGrantRevokeData(RangerResource resource,
                                                           List<HivePrincipal> hivePrincipals,
                                                           List<HivePrivilege> hivePrivileges,
                                                           boolean grantOption)
            throws HiveAccessControlException {

        GrantRevokeRequest ret = new GrantRevokeRequest();

        ret.setGrantor("rangeradmin");
        ret.setGrantorGroups(Collections.singleton("admin"));
        ret.setDelegateAdmin(grantOption ? Boolean.TRUE : Boolean.FALSE);
        ret.setEnableAudit(Boolean.TRUE);
        ret.setReplaceExistingPermissions(Boolean.FALSE);

        String database = StringUtils.isEmpty(resource.getDatabase()) ? "*" : resource.getDatabase();
        String table = StringUtils.isEmpty(resource.getTable()) ? "*" : resource.getTable();
        String column = StringUtils.isEmpty(resource.getColumn()) ? "*" : resource.getColumn();

        Map<String, String> mapResource = new HashMap<String, String>();
        mapResource.put(RangerHiveResource.KEY_DATABASE, database);
        mapResource.put(RangerHiveResource.KEY_TABLE, table);
        mapResource.put(RangerHiveResource.KEY_COLUMN, column);

        ret.setResource(mapResource);

        for (HivePrincipal principal : hivePrincipals) {
            switch (principal.getType()) {
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

        for (HivePrivilege privilege : hivePrivileges) {
            String privName = privilege.getName();

            if (StringUtils.equalsIgnoreCase(privName, HiveAccessType.ALL.name()) ||
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

    /**
     * parse arguments
     * <pre>
     *   -sentry_conf <filepath>     sentry config file path
     *   -m,--migrate
     *   -ranger_conf <filepath> ranger config file path
     * </pre>
     *
     * @param args
     */
    protected boolean parseArgs(String[] args) throws Exception {
        Options options = new Options();


        Option migrateOpt = new Option("m", "migrate", false,
                "Migrate Permission Information");
        migrateOpt.setRequired(true);
        options.addOption(migrateOpt);

        // file path of sentry-site
        Option sentrySitePathOpt = new Option("s", "sentry-site file path");
        sentrySitePathOpt.setRequired(true);
        options.addOption(sentrySitePathOpt);

        // file path of ranger configuration
        Option rangerConf = new Option("r", "Ranger configuration file path");
        rangerConf.setRequired(true);
        options.addOption(rangerConf);

        try {
            Parser parser = new GnuParser();

            CommandLine cmd = parser.parse(options, args);

            for (Option opt : cmd.getOptions()) {
                if (opt.getOpt().equals("m")) {
                    doMigration = true;
                } else if (opt.getOpt().equals("r")) {
                    sentryConfig = opt.getValue();
                } else if (opt.getOpt().equals("s")) {
                    rangerConfig = opt.getValue();
                }
            }

            if (!doMigration) {
                throw new IllegalArgumentException("No action specified");
            }
        } catch (ParseException pe) {
            System.out.println(pe.getMessage());
            return false;
        }
        return true;
    }

    class RangerExporter implements Runnable {
        private RangerSentryRESTClient rangerClient;
        TSentryAuthorizable authorizable;
        Map<TSentryPrincipal, List<TPrivilege>> permissionInfo;
        RangerExporter(TSentryAuthorizable authorizable,
                       Map<TSentryPrincipal, List<TPrivilege>> permissions) {
            rangerClient = createAdminClient();
            this.authorizable = authorizable;
            this.permissionInfo = permissions;
        }
        private RangerSentryRESTClient createAdminClient() {
            if (LOG.isDebugEnabled()) {
                LOG.debug("==> RangerBasePlugin.createAdminClient(" + rangerServiceName + ", " + applicationId + ", " + servicePropertyPrefix + ")");
            }

            RangerSentryRESTClient ret = null;

            String propertyName = servicePropertyPrefix + ".policy.source.impl";
            String policySourceImpl = RangerConfiguration.getInstance().get(propertyName);

            if (StringUtils.isEmpty(policySourceImpl)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Value for property[%s] was null or empty. Unexpected! Will use policy source of type[%s]", propertyName, RangerAdminRESTClient.class.getName()));
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(String.format("Value for property[%s] was [%s].", propertyName, policySourceImpl));
                }
                try {

                    ret = RangerSentryRESTClient.class.newInstance();
                } catch (Exception excp) {
                    LOG.error("failed to instantiate policy source of type '" + policySourceImpl + "'. Will use policy source of type '" + RangerAdminRESTClient.class.getName() + "'", excp);
                }
            }

            if (ret == null) {
                ret = new RangerSentryRESTClient();
            }

            ret.init(rangerServiceName, applicationId, servicePropertyPrefix);

            if (LOG.isDebugEnabled()) {
                LOG.debug("<== RangerBasePlugin.createAdminClient(" + rangerServiceName + ", " + applicationId + ", " + servicePropertyPrefix + "): policySourceImpl=" + policySourceImpl + ", client=" + ret);
            }
            return ret;
        }

        private long grantRangerPermission(TSentryAuthorizable authorizable,
                                   Map<TSentryPrincipal, List<TPrivilege>> permissions) {
            // For each entry in the mapping create HivePrivilegeObject and grant principals with the privileges.
            // Construct grant request
            HivePrivilegeObject hivePrivObject = null;
            if (!authorizable.getUri().isEmpty()) {
                System.out.println("URL permission not supported");
            }
            if (!authorizable.getColumn().isEmpty()) {
                // Column permission
                hivePrivObject = new HivePrivilegeObject(authorizable.getDb(), authorizable.getTable(),
                        Collections.singletonList(authorizable.getColumn()));
            } else if (!authorizable.getTable().isEmpty()) {
                // Table Permission
                hivePrivObject = new HivePrivilegeObject(HivePrivilegeObject.HivePrivilegeObjectType.TABLE_OR_VIEW, authorizable.getDb(), authorizable.getTable());

            } else if (!authorizable.getDb().isEmpty()) {
                //Database Permission
                hivePrivObject = new HivePrivilegeObject(HivePrivilegeObject.HivePrivilegeObjectType.DATABASE, authorizable.getDb(), "*");
            } else if (!authorizable.getServer().isEmpty()) {
                // Server level permission
                hivePrivObject = new HivePrivilegeObject(HivePrivilegeObject.HivePrivilegeObjectType.GLOBAL, authorizable.getServer(), "*");
            }

            RangerResource resource = getHiveResource(HiveOperationType.GRANT_PRIVILEGE, hivePrivObject);
            try {
//            System.out.println("Exporting permission for " + authorizable.toString());
                return rangerClient.ingestPolicy(resource, permissions);
            } catch (Exception e) {

            }
            return 0;
        }

        public void run() {
            grantRangerPermission(authorizable, permissionInfo);
        }
    }
}
