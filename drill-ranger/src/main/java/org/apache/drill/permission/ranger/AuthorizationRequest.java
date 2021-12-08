package org.apache.drill.permission.ranger;

import java.util.Set;

public class AuthorizationRequest {

    private Integer requestId;
    private String user;
    private String clientIp;
    private String context;
    private Set<ResourceAccess> access;

    /**
     * Returns request id.
     * @return id of the request
     */
    public Integer getRequestId() {
        return requestId;
    }

    /**
     * Sets request id.
     * @param requestId id of the request
     */
    public void setRequestId(Integer requestId) {
        this.requestId = requestId;
    }

    /**
     * Returns user name for the user submitting the access request.
     * @return name of the user
     */
    public String getUser() {
        return user;
    }

    /**
     * Sets user name for the user submitting the access request.
     * @param user name of the user
     */
    public void setUser(String user) {
        this.user = user;
    }

    /**
     * Returns IP address of the client where the user request is made from.
     * @return IP address of the user's client
     */
    public String getClientIp() {
        return clientIp;
    }

    /**
     * Sets IP address of the client where the user request is made from.
     * @param clientIp IP address of the user's client
     */
    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    /**
     * Returns context of the request, usually a SQL query that the user ran
     * @return context of the request
     */
    public String getContext() {
        return context;
    }

    /**
     * Sets the context of the request, usually a SQL query that the user ran
     * @param context context of the request
     */
    public void setContext(String context) {
        this.context = context;
    }

    /**
     * Returns a set of <code>ResourceAccess</code> objects.
     * @return s set of <code>ResourceAccess</code> objects
     */
    public Set<ResourceAccess> getAccess() {
        return access;
    }

    /**
     * Sets <code>ResourceAccess</code> objects
     * @param access a set of <code>ResourceAccess</code> objects
     */
    public void setAccess(Set<ResourceAccess> access) {
        this.access = access;
    }

}
