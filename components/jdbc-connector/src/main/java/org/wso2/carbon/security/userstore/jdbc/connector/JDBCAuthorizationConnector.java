/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.userstore.jdbc.connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.caas.user.core.util.UserCoreUtil;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.security.userstore.jdbc.util.DatabaseUtil;
import org.wso2.carbon.security.userstore.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.security.userstore.jdbc.util.UnitOfWork;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.sql.DataSource;

/**
 * JDBC connector for authorization store.
 * @since 1.0.0
 */
public class JDBCAuthorizationConnector extends JDBCStoreConnector implements AuthorizationStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCAuthorizationConnector.class);

    private String authorizationStoreId;
    private AuthorizationConnectorConfig authorizationStoreConfig;
    private DataSource dataSource;

    public void init(String storeId, AuthorizationConnectorConfig authorizationStoreConfig)
            throws AuthorizationStoreException {

        Properties properties = authorizationStoreConfig.getStoreProperties();
        this.authorizationStoreId = storeId;
        this.authorizationStoreConfig = authorizationStoreConfig;

        try {
            this.dataSource = DatabaseUtil.getInstance().getDataSource(properties
                    .getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new AuthorizationStoreException("Error while setting the data source.", e);
        }

        loadQueries(properties);

        if (log.isDebugEnabled()) {
            log.debug("JDBC authorization store with the id of '{}' initialized.", authorizationStoreId);
        }
    }

    @Override
    public String getAuthorizationStoreId() {
        return authorizationStoreId;
    }

    @Override
    public Role.RoleBuilder getRole(String roleName) throws AuthorizationStoreException, RoleNotFoundException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_NAME, roleName);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new RoleNotFoundException("No role found for the given name in " + authorizationStoreId);
                }

                String roleId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);

                if (log.isDebugEnabled()) {
                    log.debug("Role with role name: {} and role id: {} retrieved from authorization store: {}.",
                            roleName, roleId, authorizationStoreId);
                }

                return new Role.RoleBuilder().setRoleName(roleName).setRoleId(roleId)
                        .setAuthorizationStoreId(authorizationStoreId);
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving the role.", e);
        }
    }

    @Override
    public Permission.PermissionBuilder getPermission(Resource resource, Action action)
            throws AuthorizationStoreException, PermissionNotFoundException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSION));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_DOMAIN,
                    resource.getResourceDomain());
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_NAME,
                    resource.getResourceId());
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ACTION_DOMAIN,
                    action.getActionDomain());
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ACTION_NAME, action.getAction());

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new PermissionNotFoundException("No permission found for the given name in "
                            + authorizationStoreId);
                }

                String permissionId = resultSet.getString(DatabaseColumnNames.Permission.PERMISSION_ID);
                String userId = resultSet.getString(DatabaseColumnNames.Resource.USER_UNIQUE_ID);
                String identityStoreId = resultSet.getString(DatabaseColumnNames.Resource.IDENTITY_STORE_ID);

                resource = new Resource(resource.getResourceDomain(), resource.getResourceId(), userId,
                        identityStoreId);

                if (log.isDebugEnabled()) {
                    log.debug("Permission with permission id: {} retrieved from authorization store: {}.",
                            permissionId, authorizationStoreId);
                }

                return new Permission.PermissionBuilder(resource, action, permissionId, authorizationStoreId);
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving the role.", e);
        }
    }

    @Override
    public List<Role.RoleBuilder> getRolesForUser(String userId, String identityStoreId)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_USER));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Role.RoleBuilder> roles = new ArrayList<>();
                while (resultSet.next()) {
                    String roleName = resultSet.getString(DatabaseColumnNames.Role.ROLE_NAME);
                    String roleUniqueId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);
                    roles.add(new Role.RoleBuilder().setRoleName(roleName).setRoleId(roleUniqueId)
                            .setAuthorizationStoreId(authorizationStoreId));
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} roles retrieved successfully for user: {} from authorization store: {}.",
                            roles.size(), userId, authorizationStoreId);
                }

                return roles;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving roles for user.", e);
        }
    }

    @Override
    public List<Role.RoleBuilder> getRolesForGroup(String groupId, String identityStoreId)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_GROUP));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Role.RoleBuilder> roles = new ArrayList<>();

                while (resultSet.next()) {
                    String roleId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);
                    String roleName = resultSet.getString(DatabaseColumnNames.Role.ROLE_NAME);
                    roles.add(new Role.RoleBuilder().setRoleName(roleName).setRoleId(roleId)
                            .setAuthorizationStoreId(authorizationStoreId));
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} roles retrieved successfully for group: {} from from authorization store: {}.",
                            roles.size(), groupId, authorizationStoreId);
                }

                return roles;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving the roles of group.", e);
        }
    }

    @Override
    public List<Permission.PermissionBuilder> getPermissionsForRole(String roleId, Resource resource)
            throws AuthorizationStoreException {

        String resourceDomain = resource.getResourceDomain().replace('*', '?');
        String resourceName = resource.getResourceId().replace('*', '?');

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSIONS_FOR_ROLE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_DOMAIN, resourceDomain);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_NAME, resourceName);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Permission.PermissionBuilder> permissionBuilders = new ArrayList<>();
                while (resultSet.next()) {

                    String domain = resultSet.getString(DatabaseColumnNames.Resource.DOMAIN_ID);
                    String name = resultSet.getString(DatabaseColumnNames.Resource.RESOURCE_NAME);
                    String userId = resultSet.getString(DatabaseColumnNames.Resource.USER_UNIQUE_ID);
                    String identityStoreId = resultSet.getString(DatabaseColumnNames.Resource.IDENTITY_STORE_ID);

                    String actionDomain = resultSet.getString(DatabaseColumnNames.Action.DOMAIN_ID);
                    String actionName = resultSet.getString(DatabaseColumnNames.Action.ACTION_NAME);

                    String permissionId = resultSet.getString(DatabaseColumnNames.Permission.PERMISSION_ID);

                    Resource res = new Resource(domain, name, userId, identityStoreId);
                    Action action = new Action(actionDomain, actionName);

                    permissionBuilders.add(new Permission.PermissionBuilder(res, action, permissionId,
                            authorizationStoreId));
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} permissions retrieved successfully for role: {} from from authorization store: {}.",
                            permissionBuilders.size(), roleId, authorizationStoreId);
                }

                return permissionBuilders;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving permissions for role.", e);
        }
    }

    @Override
    public Permission.PermissionBuilder addPermission(Resource resource, Action action)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            // Add resource if not exists.
            NamedPreparedStatement getResourceIdPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_RESOURCE_ID));
            getResourceIdPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_DOMAIN,
                    resource.getResourceDomain());
            getResourceIdPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_NAME,
                    resource.getResourceId());

            long resourceId;

            try (ResultSet resultSet = getResourceIdPreparedStatement.getPreparedStatement().executeQuery()) {
                if (resultSet.next()) {
                    resourceId = resultSet.getLong(1);
                } else {

                    if (resource.getOwner() == null) {
                        throw new AuthorizationStoreException("Resource owner cannot be null.");
                    }

                    NamedPreparedStatement addResourcePreparedStatement = new NamedPreparedStatement(
                            unitOfWork.getConnection(),
                            sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_RESOURCE));
                    addResourcePreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_DOMAIN,
                            resource.getResourceDomain());
                    addResourcePreparedStatement.setString(ConnectorConstants.SQLPlaceholders.RESOURCE_NAME,
                            resource.getResourceId());
                    addResourcePreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID,
                            resource.getOwner().getUserId());
                    addResourcePreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            resource.getOwner().getIdentityStoreId());

                    addResourcePreparedStatement.getPreparedStatement().executeUpdate();

                    try (ResultSet rs = addResourcePreparedStatement.getPreparedStatement().getGeneratedKeys()) {
                        if (!rs.next()) {
                            throw new AuthorizationStoreException("Error occurred while adding the resource.");
                        }
                        resourceId = rs.getLong(1);
                    }
                }
            }

            // Add action if not exists.
            NamedPreparedStatement getActionPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ACTION_ID));
            getActionPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ACTION_DOMAIN,
                    action.getActionDomain());
            getActionPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ACTION_NAME,
                    action.getAction());

            long actionId;

            try (ResultSet resultSet = getActionPreparedStatement.getPreparedStatement().executeQuery()) {
                if (resultSet.next()) {
                    actionId = resultSet.getLong(1);
                } else {
                    NamedPreparedStatement addActionPreparedStatement = new NamedPreparedStatement(
                            unitOfWork.getConnection(),
                            sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ACTION));
                    addActionPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ACTION_DOMAIN,
                            action.getActionDomain());
                    addActionPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ACTION_NAME,
                            action.getAction());

                    addActionPreparedStatement.getPreparedStatement().executeUpdate();

                    try (ResultSet rs = addActionPreparedStatement.getPreparedStatement().getGeneratedKeys()) {
                        if (!rs.next()) {
                            throw new AuthorizationStoreException("Error occurred while adding the action.");
                        }
                        actionId = rs.getLong(1);
                    }
                }
            }

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSION));

            String permissionId = UserCoreUtil.getRandomId();

            namedPreparedStatement.setLong(ConnectorConstants.SQLPlaceholders.RESOURCE_ID, resourceId);
            namedPreparedStatement.setLong(ConnectorConstants.SQLPlaceholders.ACTION_ID, actionId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PERMISSION_ID, permissionId);

            namedPreparedStatement.getPreparedStatement().execute();

            if (log.isDebugEnabled()) {
                log.debug("Permission with resource id: {}, action: {}, permission id: {} is added to " +
                        "authorization store: {}.", resource.getResourceString(), action.getActionString(),
                        permissionId, authorizationStoreId);
            }

            return new Permission.PermissionBuilder(resource, action, permissionId, authorizationStoreId);
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while adding the permission.", e);
        }
    }

    @Override
    public Role.RoleBuilder addRole(String roleName, List<Permission> permissions) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement addRolePreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLE));

            String roleUniqueId = UserCoreUtil.getRandomId();

            addRolePreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_NAME, roleName);
            addRolePreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_UNIQUE_ID, roleUniqueId);
            addRolePreparedStatement.getPreparedStatement().executeUpdate();
            ResultSet resultSet = addRolePreparedStatement.getPreparedStatement().getGeneratedKeys();

            if (!resultSet.next()) {
                throw new AuthorizationStoreException("Failed to add the role.");
            }

            long roleId = resultSet.getLong(1);

            if (log.isDebugEnabled()) {
                log.debug("Role with role id: {} added to {}.", roleUniqueId, authorizationStoreId);
            }

            NamedPreparedStatement addRolePermissionPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE));

            for (Permission permission : permissions) {
                addRolePermissionPreparedStatement.setLong(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                addRolePermissionPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PERMISSION_ID,
                        permission.getPermissionId());
                addRolePermissionPreparedStatement.getPreparedStatement().addBatch();
            }

            addRolePermissionPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (log.isDebugEnabled()) {
                log.debug("{} number of permissions added to the role with role id: {} from authorization store: {}.",
                        permissions.size(), roleId, authorizationStoreId);
            }

            return new Role.RoleBuilder().setAuthorizationStoreId(authorizationStoreId).setRoleName(roleName)
                    .setRoleId(roleUniqueId);

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while adding the role.", e);
        }
    }

    @Override
    public boolean isUserInRole(String userId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_IS_USER_IN_ROLE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID, identityStoreId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_NAME, roleName);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                return resultSet.next();
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while checking is user in role.", e);
        }
    }

    @Override
    public boolean isGroupInRole(String groupId, String identityStoreId, String roleName)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_IS_GROUP_IN_ROLE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID, identityStoreId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_NAME, roleName);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                return resultSet.next();
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while checking is user in role.", e);
        }
    }

    @Override
    public List<User.UserBuilder> getUsersOfRole(String roleId) throws AuthorizationStoreException {

        List<User.UserBuilder> userBuilders = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USERS_OF_ROLE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                while (resultSet.next()) {
                    User.UserBuilder userBuilder = new User.UserBuilder();
                    userBuilder.setUserId(resultSet.getString(DatabaseColumnNames.UserRole.USER_UNIQUE_ID))
                            .setIdentityStoreId(resultSet.getString(DatabaseColumnNames.UserRole.IDENTITY_STORE_ID));
                    userBuilders.add(userBuilder);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} users of role: {} retrieved from from authorization store: {}.", userBuilders.size(),
                        roleId, authorizationStoreId);
            }

            return userBuilders;
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving users of the role.", e);
        }
    }

    @Override
    public List<Group.GroupBuilder> getGroupsOfRole(String roleId) throws AuthorizationStoreException {

        List<Group.GroupBuilder> groupBuilders = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUPS_OF_ROLE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                while (resultSet.next()) {
                    Group.GroupBuilder groupBuilder = new Group.GroupBuilder();
                    groupBuilder.setGroupId(resultSet.getString(DatabaseColumnNames.GroupRole.GROUP_UNIQUE_ID))
                            .setIdentityStoreId(resultSet.getString(DatabaseColumnNames.GroupRole.IDENTITY_STORE_ID));
                    groupBuilders.add(groupBuilder);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} groups of role: {} retrieved from from authorization store: {}.", groupBuilders.size(),
                        roleId, authorizationStoreId);
            }

            return groupBuilders;
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving groups of the role.", e);
        }
    }

    @Override
    public void deleteRole(String roleId) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_ROLE));

            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
            namedPreparedStatement.getPreparedStatement().executeUpdate();

            if (log.isDebugEnabled()) {
                log.debug("Role with id: {} deleted from {}.", roleId, authorizationStoreId);
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while deleting the role.", e);
        }
    }

    @Override
    public void deletePermission(String permissionId) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_PERMISSION));

            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PERMISSION_ID, permissionId);
            namedPreparedStatement.getPreparedStatement().executeUpdate();

            if (log.isDebugEnabled()) {
                log.debug("Permission with id: {} deleted from from authorization store: {}.", permissionId,
                        authorizationStoreId);
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while deleting the permission.", e);
        }
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> roles)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement deleteRolesOfUserPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_ROLES_FROM_USER));

            deleteRolesOfUserPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            deleteRolesOfUserPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                    identityStoreId);
            deleteRolesOfUserPreparedStatement.getPreparedStatement().executeUpdate();

            if (log.isDebugEnabled()) {
                log.debug("All roles deleted from user id: {} from from authorization store: {}.", userId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addRolesToUserPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

            for (Role role : roles) {
                addRolesToUserPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
                addRolesToUserPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                        identityStoreId);
                addRolesToUserPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, role.getRoleId());
                addRolesToUserPreparedStatement.getPreparedStatement().addBatch();
            }

            addRolesToUserPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (log.isDebugEnabled()) {
                log.debug("{} roles added to the user: {} in authorization store: {}.", roles.size(), userId,
                        authorizationStoreId);
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating roles in user.", e);
        }
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> addList, List<Role> removeList)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            if (removeList != null && !removeList.isEmpty()) {

                NamedPreparedStatement unAssingPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_ROLES_FROM_USER));

                for (Role role : removeList) {
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            identityStoreId);
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, role.getRoleId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} roles deleted from user: {} in authorization store: {}.", removeList.size(),
                            userId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

                for (Role role : addList) {
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            identityStoreId);
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, role.getRoleId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} roles added to the user: {} in authorization store: {}.", addList.size(), userId,
                            authorizationStoreId);
                }
            }
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating roles in the user.", e);
        }
    }

    @Override
    public void updateUsersInRole(String roleId, List<User> users) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement deleteUsersPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USERS_FROM_ROLE));

            deleteUsersPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);

            if (log.isDebugEnabled()) {
                log.debug("All users of the role: {} deleted from from authorization store: {}.", roleId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addUsersPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

            for (User user : users) {
                addUsersPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, user.getUserId());
                addUsersPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                        user.getIdentityStoreId());
                addUsersPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                addUsersPreparedStatement.getPreparedStatement().addBatch();
            }

            addUsersPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (log.isDebugEnabled()) {
                log.debug("{} users added to the role: {} in authorization store: {}.", users.size(), roleId,
                        authorizationStoreId);
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating users in the role.", e);
        }
    }

    @Override
    public void updateUsersInRole(String roleId, List<User> addList, List<User> removeList)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            if (removeList != null && !removeList.isEmpty()) {

                NamedPreparedStatement unAssingPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_ROLES_FROM_USER));

                for (User user : removeList) {
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, user.getUserId());
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            user.getIdentityStoreId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} users deleted from the role: {} in authorization store: {}.", removeList.size(),
                            roleId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

                for (User user : addList) {
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, user.getUserId());
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            user.getIdentityStoreId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} users added to the role: {} in authorization store: {}.", addList.size(), roleId,
                            authorizationStoreId);
                }
            }

            unitOfWork.endTransaction();

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating users in the role.", e);
        }
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> roles)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement deleteRolesOfGroupPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_ROLES_FROM_GROUP));

            deleteRolesOfGroupPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);
            deleteRolesOfGroupPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                    identityStoreId);
            deleteRolesOfGroupPreparedStatement.getPreparedStatement().executeUpdate();

            if (log.isDebugEnabled()) {
                log.debug("All roles deleted from the group: {} in authorization store: {}.", groupId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addRolesToGroupPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

            for (Role role : roles) {
                addRolesToGroupPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);
                addRolesToGroupPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                        identityStoreId);
                addRolesToGroupPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID,
                        role.getRoleId());
                addRolesToGroupPreparedStatement.getPreparedStatement().addBatch();
            }

            addRolesToGroupPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (log.isDebugEnabled()) {
                log.debug("{} roles added to the group: {} in authorization store: {}.", roles.size(), groupId,
                        authorizationStoreId);
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating roles in group.", e);
        }
    }

    @Override
    public void updateRolesInGroup(String groupId, String identityStoreId, List<Role> addList, List<Role> removeList)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            if (removeList != null && !removeList.isEmpty()) {

                NamedPreparedStatement unAssingPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_ROLES_FROM_GROUP));

                for (Role role : removeList) {
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            identityStoreId);
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, role.getRoleId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} roles removed from the group: {} in authorization store: {}.", removeList.size(),
                            groupId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

                for (Role role : addList) {
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            identityStoreId);
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, role.getRoleId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} roles added to the group: {} in authorization store: {}.", addList.size(), groupId,
                            authorizationStoreId);
                }
            }

            unitOfWork.endTransaction();

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating roles in the group.", e);
        }
    }

    @Override
    public void updateGroupsInRole(String roleId, List<Group> groups) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement deleteGroupsPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUPS_FROM_ROLE));

            deleteGroupsPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);

            if (log.isDebugEnabled()) {
                log.debug("All groups deleted from the role: {} in authorization store: {}.", roleId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addGroupsPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

            for (Group group : groups) {
                addGroupsPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, group.getGroupId());
                addGroupsPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                        group.getIdentityStoreId());
                addGroupsPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                addGroupsPreparedStatement.getPreparedStatement().addBatch();
            }

            addGroupsPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (log.isDebugEnabled()) {
                log.debug("{} groups added to the role: {} in authorization store: {}.", groups.size(), roleId,
                        authorizationStoreId);
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating groups in the role.", e);
        }
    }

    @Override
    public void updateGroupsInRole(String roleId, List<Group> addList, List<Group> removeList)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            if (removeList != null && !removeList.isEmpty()) {

                NamedPreparedStatement unAssingPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_ROLES_FROM_GROUP));

                for (Group group : removeList) {
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID,
                            group.getGroupId());
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            group.getIdentityStoreId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} groups removed from the role: {} in authorization store: {}.", removeList.size(),
                            roleId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

                for (Group group : addList) {
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, group.getGroupId());
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.IDENTITY_STORE_ID,
                            group.getIdentityStoreId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} groups added to the role {} in authorization store: {}.", addList.size(), roleId,
                            authorizationStoreId);
                }
            }

            unitOfWork.endTransaction();

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating groups in the role.", e);
        }
    }

    @Override
    public void updatePermissionsInRole(String roleId, List<Permission> permissions)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement deletePermissionPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_PERMISSIONS_FROM_ROLE));

            deletePermissionPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
            deletePermissionPreparedStatement.getPreparedStatement().executeUpdate();

            if (log.isDebugEnabled()) {
                log.debug("All permissions deleted in the role {} in authorization store: {}.", roleId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addPermissionsPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE_BY_UNIQUE_ID));

            for (Permission permission : permissions) {
                addPermissionsPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PERMISSION_ID,
                        permission.getPermissionId());
                addPermissionsPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                addPermissionsPreparedStatement.getPreparedStatement().addBatch();
            }

            addPermissionsPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (log.isDebugEnabled()) {
                log.debug("{} permissions added to the role: {} in authorization store: {}.", permissions.size(),
                        roleId, authorizationStoreId);
            }

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating permissions in the role.", e);
        }
    }

    @Override
    public void updatePermissionsInRole(String roleId, List<Permission> addList, List<Permission> removeList)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            if (removeList != null && !removeList.isEmpty()) {

                NamedPreparedStatement unAssingPreparedStatement = new NamedPreparedStatement(
                        unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_PERMISSIONS_FROM_ROLE));

                for (Permission permission : removeList) {
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                    unAssingPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PERMISSION_ID,
                            permission.getPermissionId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} permissions deleted from the role: {} in authorization store: {}.", removeList.size(),
                            roleId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE_BY_UNIQUE_ID));

                for (Permission permission : addList) {
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ROLE_ID, roleId);
                    assignPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PERMISSION_ID,
                            permission.getPermissionId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }

                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (log.isDebugEnabled()) {
                    log.debug("{} permissions added to the role: {} in authorization store: {}.", addList.size(),
                            roleId, authorizationStoreId);
                }
            }

            unitOfWork.endTransaction();

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while updating permissions in the role.", e);
        }
    }

    @Override
    public AuthorizationConnectorConfig getAuthorizationStoreConfig() {
        return authorizationStoreConfig;
    }
}
