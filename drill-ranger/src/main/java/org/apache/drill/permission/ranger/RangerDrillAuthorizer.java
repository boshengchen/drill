package org.apache.drill.permission.ranger;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResource;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.eclipse.jetty.http.MultiPartParser.LOG;

public class RangerDrillAuthorizer {

    private static final Logger logger = LoggerFactory.getLogger(RangerDrillAuthorizer.class);

    private static volatile RangerDrillPlugin drillPlugin = null;

    public RangerDrillAuthorizer() {
    }

    public void init() {
        RangerDrillPlugin plugin = drillPlugin;
        if (plugin == null) {
            synchronized (RangerDrillAuthorizer.class) {
                plugin = drillPlugin;
                if (plugin == null) {
                    plugin = new RangerDrillPlugin();
                    plugin.init();
                    drillPlugin = plugin;
                }
            }
        }
    }

    /**
     * Validates that authorization requests do not have any missing data.
     *
     * @param request authorization request
     * @throws IllegalArgumentException if any data is missing
     */
    private void validateRequest(AuthorizationRequest request) {
        LOG.debug("Validating authorization request");

        if (request == null) {
            throw new IllegalArgumentException("request is null");
        }

        if (request.getRequestId() == null) {
            throw new IllegalArgumentException("requestId field is missing or null in the request");
        }

        if (StringUtils.isEmpty(request.getUser())) {
            throw new IllegalArgumentException("user field is missing or empty in the request");
        }

        if (StringUtils.isEmpty(request.getClientIp())) {
            throw new IllegalArgumentException("clientIp field is missing or empty in the request");
        }

        if (StringUtils.isEmpty(request.getContext())) {
            throw new IllegalArgumentException("context field is missing or empty in the request");
        }

        Set<ResourceAccess> accessSet = request.getAccess();
        if (CollectionUtils.isEmpty(accessSet)) {
            throw new IllegalArgumentException("access field is missing or empty in the request");
        }

        for (ResourceAccess access : accessSet) {
            validateResourceAccess(access);
        }

        LOG.debug("Successfully validated authorization request");
    }

    /**
     * Validates that resource access does not have any missing data.
     *
     * @param access resource access data
     * @throws IllegalArgumentException if any data is missing
     */
    private void validateResourceAccess(ResourceAccess access) {
        Map<DrillResource, String> resourceMap = access.getResource();
        if (MapUtils.isEmpty(resourceMap)) {
            throw new IllegalArgumentException("resource field is missing or empty in the request");
        }
        for (Map.Entry<DrillResource, String> resourceEntry : resourceMap.entrySet()) {
            if (StringUtils.isEmpty(resourceEntry.getValue())) {
                throw new IllegalArgumentException(
                        String.format("resource value is missing for key=%s in the request", resourceEntry.getKey())
                );
            }
        }
        if (CollectionUtils.isEmpty(access.getPrivileges())) {
            throw new IllegalArgumentException("set of privileges is missing empty in the request");
        }
    }

    public boolean isAccessAllowed(AuthorizationRequest request) {

        // validate request to make sure no data is missing
        validateRequest(request);

        // iterate over resource requests, augment processed ones with the decision and add to the response
        for (ResourceAccess resourceAccess : request.getAccess()) {
            boolean accessAllowed = authorizeResource(resourceAccess, request.getUser(), request.getClientIp(), request.getContext());
            if (!accessAllowed) {
                return accessAllowed;
            }
        }
        return true;
    }

    /**
     * Authorizes access to a single resource for a given user.
     *
     * @param resourceAccess resource to authorize access to
     * @param user           user requesting authorization
     * @return true if access is authorized, false otherwise
     */
    private boolean authorizeResource(ResourceAccess resourceAccess, String user, String clientIp, String context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Request: access for user=%s to resource=%s with privileges=%s",
                    user, resourceAccess.getResource(), resourceAccess.getPrivileges()));
        }

        RangerAccessResourceImpl rangerResource = new RangerAccessResourceImpl();
        //resource.setOwnerUser();
        for (Map.Entry<DrillResource, String> resourceEntry : resourceAccess.getResource().entrySet()) {
            rangerResource.setValue(resourceEntry.getKey().name(), resourceEntry.getValue());
        }
        // determine user groups
        Set<String> userGroups = getUserGroups(user);

        boolean accessAllowed = true;
        // iterate over all privileges requested
        for (DrillPrivilege privilege : resourceAccess.getPrivileges()) {
            boolean privilegeAuthorized = authorizeResourcePrivilege(rangerResource, privilege.name(), user, userGroups, clientIp, context);
            // ALL model of evaluation -- all privileges must be authorized for access to be allowed
            if (!privilegeAuthorized) {
                accessAllowed = false;
                break; // terminate early if even a single privilege is not authorized
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Decision: accessAllowed=%s for user=%s to resource=%s with privileges=%s",
                    accessAllowed, user, resourceAccess.getResource(), resourceAccess.getPrivileges()));
        }

        return accessAllowed;
    }

    /**
     * Authorizes access of a given type (privilege) to a single resource for a given user.
     *
     * @param rangerResource resource to authorize access to
     * @param accessType     privilege requested for a given resource
     * @param user           user requesting authorization
     * @param userGroups     groups a user belongs to
     * @return true if access is authorized, false otherwise
     */
    private boolean authorizeResourcePrivilege(RangerAccessResource rangerResource, String accessType, String user, Set<String> userGroups, String clientIp, String context) {
        RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl(rangerResource, accessType, user, userGroups);
        rangerRequest.setAccessTime(new Date());
        rangerRequest.setAction(accessType);
        rangerRequest.setClientIPAddress(clientIp);
        rangerRequest.setRequestData(context);
        RangerAccessResult result = drillPlugin.isAccessAllowed(rangerRequest);
        boolean accessAllowed = result != null && result.getIsAllowed();

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("--- RangerDecision: accessAllowed=%s for user=%s to resource=%s with privileges=%s, result present=%s",
                    accessAllowed, user, rangerResource.getAsString(), accessType, result != null));
        }

        return accessAllowed;
    }

    /**
     * Returns a set of groups the user belongs to
     *
     * @param user user name
     * @return set of groups for the user
     */
    private Set<String> getUserGroups(String user) {
        String[] userGroups = null;
        try {
            UserGroupInformation ugi = UserGroupInformation.createRemoteUser(user);
            userGroups = ugi.getGroupNames();
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Determined user=%s belongs to groups=%s", user, Arrays.toString(userGroups)));
            }
        } catch (Throwable e) {
            LOG.warn("Failed to determine groups for user=" + user, e);
        }
        return userGroups == null ? Collections.<String>emptySet() : new HashSet<String>(Arrays.asList(userGroups));
    }
}

class RangerDrillPlugin extends RangerBasePlugin {
    public RangerDrillPlugin() {
        super("drill", "drill");
    }

    public void init() {
        super.init();
        RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
        super.setResultProcessor(auditHandler);
    }
}
