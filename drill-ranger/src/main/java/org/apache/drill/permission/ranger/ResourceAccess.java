package org.apache.drill.permission.ranger;

import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Model object for requesting access to a single resource.
 */
public class ResourceAccess {

    private Map<DrillResource, String> resource;
    private Set<DrillPrivilege> privileges;
    private boolean allowed = false;

    public Set<DrillPrivilege> getPrivileges() {
        return privileges;
    }

    public void setPrivileges(Set<DrillPrivilege> privileges) {
        this.privileges = privileges;
    }

    public boolean isAllowed() {
        return allowed;
    }

    public void setAllowed(boolean allowed) {
        this.allowed = allowed;
    }

    public Map<DrillResource, String> getResource() {
        return resource;
    }

    public void setResource(Map<DrillResource, String> resource) {
        this.resource = resource;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("resource", resource)
                .append("privileges", privileges)
                .append("allowed", allowed)
                .toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ResourceAccess that = (ResourceAccess) o;
        return allowed == that.allowed &&
                Objects.equals(resource, that.resource) &&
                Objects.equals(privileges, that.privileges);
    }

    @Override
    public int hashCode() {
        return Objects.hash(resource, privileges, allowed);
    }

}
