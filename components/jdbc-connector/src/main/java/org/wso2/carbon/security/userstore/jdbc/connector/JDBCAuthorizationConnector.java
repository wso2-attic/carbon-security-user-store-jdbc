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
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
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
    private static final boolean IS_DEBUG_ENABLED = log.isDebugEnabled();

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

        loadQueries(properties.getProperty(ConnectorConstants.DATABASE_TYPE));

        if (IS_DEBUG_ENABLED) {
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
            namedPreparedStatement.setString("role_name", roleName);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new RoleNotFoundException("No role found for the given name in " + authorizationStoreId);
                }

                String roleId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);

                if (IS_DEBUG_ENABLED) {
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
    public Permission.PermissionBuilder getPermission(String resourceId, String action)
            throws AuthorizationStoreException, PermissionNotFoundException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSION));
            namedPreparedStatement.setString("resource_id", resourceId);
            namedPreparedStatement.setString("action", action);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new PermissionNotFoundException("No permission found for the given name in "
                            + authorizationStoreId);
                }

                String permissionId = resultSet.getString(DatabaseColumnNames.Permission.PERMISSION_ID);

                if (IS_DEBUG_ENABLED) {
                    log.debug("Permission with permission id: {} retrieved from authorization store: {}.",
                            permissionId, authorizationStoreId);
                }

                return new Permission.PermissionBuilder(resourceId, action, permissionId, authorizationStoreId);
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
            namedPreparedStatement.setString("user_id", userId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Role.RoleBuilder> roles = new ArrayList<>();
                while (resultSet.next()) {
                    String roleName = resultSet.getString(DatabaseColumnNames.Role.ROLE_NAME);
                    String roleUniqueId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);
                    roles.add(new Role.RoleBuilder().setRoleName(roleName).setRoleId(roleUniqueId)
                            .setAuthorizationStoreId(authorizationStoreId));
                }

                if (IS_DEBUG_ENABLED) {
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
            namedPreparedStatement.setString("group_id", groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Role.RoleBuilder> roles = new ArrayList<>();

                while (resultSet.next()) {
                    String roleId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);
                    String roleName = resultSet.getString(DatabaseColumnNames.Role.ROLE_NAME);
                    roles.add(new Role.RoleBuilder().setRoleName(roleName).setRoleId(roleId)
                            .setAuthorizationStoreId(authorizationStoreId));
                }

                if (IS_DEBUG_ENABLED) {
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
    public List<Permission.PermissionBuilder> getPermissionsForRole(String roleId) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSIONS_FOR_ROLE));
            namedPreparedStatement.setString("role_id", roleId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Permission.PermissionBuilder> permissionBuilders = new ArrayList<>();
                while (resultSet.next()) {
                    String resourceId = resultSet.getString(DatabaseColumnNames.Permission.RESOURCE_ID);
                    String action = resultSet.getString(DatabaseColumnNames.Permission.ACTION);
                    String permissionId = resultSet.getString(DatabaseColumnNames.Permission.PERMISSION_ID);
                    permissionBuilders.add(new Permission.PermissionBuilder(resourceId, action, permissionId,
                            authorizationStoreId));
                }

                if (IS_DEBUG_ENABLED) {
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
    public Permission.PermissionBuilder addPermission(String resourceId, String action)
            throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSION));

            String permissionId = UserCoreUtil.getRandomId();

            namedPreparedStatement.setString("resource_id", resourceId);
            namedPreparedStatement.setString("action", action);
            namedPreparedStatement.setString("permission_id", permissionId);

            namedPreparedStatement.getPreparedStatement().execute();

            if (IS_DEBUG_ENABLED) {
                log.debug("Permission with resource id: {}, action: {}, permission id: {} is added to from " +
                        "authorization store: {}.", resourceId, action, permissionId, authorizationStoreId);
            }

            return new Permission.PermissionBuilder(resourceId, action,
                    permissionId, authorizationStoreId);
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

            addRolePreparedStatement.setString("role_name", roleName);
            addRolePreparedStatement.setString("role_unique_id", roleUniqueId);
            addRolePreparedStatement.getPreparedStatement().executeUpdate();
            ResultSet resultSet = addRolePreparedStatement.getPreparedStatement().getGeneratedKeys();

            if (!resultSet.next()) {
                throw new AuthorizationStoreException("Failed to add the role.");
            }

            long roleId = resultSet.getLong(1);

            if (IS_DEBUG_ENABLED) {
                log.debug("Role with role id: {} added to {}.", roleUniqueId, authorizationStoreId);
            }

            NamedPreparedStatement addRolePermissionPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE));

            for (Permission permission : permissions) {
                addRolePermissionPreparedStatement.setLong("role_id", roleId);
                addRolePermissionPreparedStatement.setString("permission_id", permission.getPermissionId());
                addRolePermissionPreparedStatement.getPreparedStatement().addBatch();
            }

            addRolePermissionPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (IS_DEBUG_ENABLED) {
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
            namedPreparedStatement.setString("user_id", userId);
            namedPreparedStatement.setString("identity_store_id", identityStoreId);
            namedPreparedStatement.setString("role_name", roleName);

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
            namedPreparedStatement.setString("group_id", groupId);
            namedPreparedStatement.setString("identity_store_id", identityStoreId);
            namedPreparedStatement.setString("role_name", roleName);

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
            namedPreparedStatement.setString("role_id", roleId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                while (resultSet.next()) {
                    User.UserBuilder userBuilder = new User.UserBuilder();
                    userBuilder.setUserId(resultSet.getString(DatabaseColumnNames.UserRole.USER_UNIQUE_ID))
                            .setIdentityStoreId(resultSet.getString(DatabaseColumnNames.UserRole.IDENTITY_STORE_ID));
                    userBuilders.add(userBuilder);
                }
            }

            if (IS_DEBUG_ENABLED) {
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
            namedPreparedStatement.setString("role_id", roleId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                while (resultSet.next()) {
                    Group.GroupBuilder groupBuilder = new Group.GroupBuilder();
                    groupBuilder.setGroupId(resultSet.getString(DatabaseColumnNames.GroupRole.GROUP_UNIQUE_ID))
                            .setIdentityStoreId(resultSet.getString(DatabaseColumnNames.GroupRole.IDENTITY_STORE_ID));
                    groupBuilders.add(groupBuilder);
                }
            }

            if (IS_DEBUG_ENABLED) {
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

            namedPreparedStatement.setString("role_id", roleId);
            namedPreparedStatement.getPreparedStatement().executeUpdate();

            if (IS_DEBUG_ENABLED) {
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

            namedPreparedStatement.setString("permission_id", permissionId);
            namedPreparedStatement.getPreparedStatement().executeUpdate();

            if (IS_DEBUG_ENABLED) {
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

            deleteRolesOfUserPreparedStatement.setString("user_id", userId);
            deleteRolesOfUserPreparedStatement.setString("identity_store_id", identityStoreId);
            deleteRolesOfUserPreparedStatement.getPreparedStatement().executeUpdate();

            if (IS_DEBUG_ENABLED) {
                log.debug("All roles deleted from user id: {} from from authorization store: {}.", userId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addRolesToUserPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

            for (Role role : roles) {
                addRolesToUserPreparedStatement.setString("user_id", userId);
                addRolesToUserPreparedStatement.setString("identity_store_id", identityStoreId);
                addRolesToUserPreparedStatement.setString("role_id", role.getRoleId());
                addRolesToUserPreparedStatement.getPreparedStatement().addBatch();
            }

            addRolesToUserPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (IS_DEBUG_ENABLED) {
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
                    unAssingPreparedStatement.setString("user_id", userId);
                    unAssingPreparedStatement.setString("identity_store_id", identityStoreId);
                    unAssingPreparedStatement.setString("role_id", role.getRoleId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
                    log.debug("{} roles deleted from user: {} in authorization store: {}.", removeList.size(),
                            userId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

                for (Role role : addList) {
                    assignPreparedStatement.setString("user_id", userId);
                    assignPreparedStatement.setString("identity_store_id", identityStoreId);
                    assignPreparedStatement.setString("role_id", role.getRoleId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
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

            deleteUsersPreparedStatement.setString("role_id", roleId);

            if (IS_DEBUG_ENABLED) {
                log.debug("All users of the role: {} deleted from from authorization store: {}.", roleId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addUsersPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

            for (User user : users) {
                addUsersPreparedStatement.setString("user_id", user.getUserId());
                addUsersPreparedStatement.setString("identity_store_id", user.getIdentityStoreId());
                addUsersPreparedStatement.setString("role_id", roleId);
                addUsersPreparedStatement.getPreparedStatement().addBatch();
            }

            addUsersPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (IS_DEBUG_ENABLED) {
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
                    unAssingPreparedStatement.setString("role_id", roleId);
                    unAssingPreparedStatement.setString("user_id", user.getUserId());
                    unAssingPreparedStatement.setString("identity_store_id", user.getIdentityStoreId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
                    log.debug("{} users deleted from the role: {} in authorization store: {}.", removeList.size(),
                            roleId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER));

                for (User user : addList) {
                    assignPreparedStatement.setString("role_id", roleId);
                    assignPreparedStatement.setString("user_id", user.getUserId());
                    assignPreparedStatement.setString("identity_store_id", user.getIdentityStoreId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
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

            deleteRolesOfGroupPreparedStatement.setString("group_id", groupId);
            deleteRolesOfGroupPreparedStatement.setString("identity_store_id", identityStoreId);
            deleteRolesOfGroupPreparedStatement.getPreparedStatement().executeUpdate();

            if (IS_DEBUG_ENABLED) {
                log.debug("All roles deleted from the group: {} in authorization store: {}.", groupId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addRolesToGroupPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

            for (Role role : roles) {
                addRolesToGroupPreparedStatement.setString("group_id", groupId);
                addRolesToGroupPreparedStatement.setString("identity_store_id", identityStoreId);
                addRolesToGroupPreparedStatement.setString("role_id", role.getRoleId());
                addRolesToGroupPreparedStatement.getPreparedStatement().addBatch();
            }

            addRolesToGroupPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (IS_DEBUG_ENABLED) {
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
                    unAssingPreparedStatement.setString("group_id", groupId);
                    unAssingPreparedStatement.setString("identity_store_id", identityStoreId);
                    unAssingPreparedStatement.setString("role_id", role.getRoleId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
                    log.debug("{} roles removed from the group: {} in authorization store: {}.", removeList.size(),
                            groupId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

                for (Role role : addList) {
                    assignPreparedStatement.setString("group_id", groupId);
                    assignPreparedStatement.setString("identity_store_id", identityStoreId);
                    assignPreparedStatement.setString("role_id", role.getRoleId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
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

            deleteGroupsPreparedStatement.setString("role_id", roleId);

            if (IS_DEBUG_ENABLED) {
                log.debug("All groups deleted from the role: {} in authorization store: {}.", roleId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addGroupsPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

            for (Group group : groups) {
                addGroupsPreparedStatement.setString("group_id", group.getGroupId());
                addGroupsPreparedStatement.setString("identity_store_id", group.getIdentityStoreId());
                addGroupsPreparedStatement.setString("role_id", roleId);
                addGroupsPreparedStatement.getPreparedStatement().addBatch();
            }

            addGroupsPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (IS_DEBUG_ENABLED) {
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
                    unAssingPreparedStatement.setString("role_id", roleId);
                    unAssingPreparedStatement.setString("group_id", group.getGroupId());
                    unAssingPreparedStatement.setString("identity_store_id", group.getIdentityStoreId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
                    log.debug("{} groups removed from the role: {} in authorization store: {}.", removeList.size(),
                            roleId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP));

                for (Group group : addList) {
                    assignPreparedStatement.setString("role_id", roleId);
                    assignPreparedStatement.setString("group_id", group.getGroupId());
                    assignPreparedStatement.setString("identity_store_id", group.getIdentityStoreId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }
                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
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

            deletePermissionPreparedStatement.setString("role_id", roleId);
            deletePermissionPreparedStatement.getPreparedStatement().executeUpdate();

            if (IS_DEBUG_ENABLED) {
                log.debug("All permissions deleted in the role {} in authorization store: {}.", roleId,
                        authorizationStoreId);
            }

            NamedPreparedStatement addPermissionsPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE_BY_UNIQUE_ID));

            for (Permission permission : permissions) {
                addPermissionsPreparedStatement.setString("permission_id", permission.getPermissionId());
                addPermissionsPreparedStatement.setString("role_id", roleId);
                addPermissionsPreparedStatement.getPreparedStatement().addBatch();
            }

            addPermissionsPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

            if (IS_DEBUG_ENABLED) {
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
                    unAssingPreparedStatement.setString("role_id", roleId);
                    unAssingPreparedStatement.setString("permission_id", permission.getPermissionId());
                    unAssingPreparedStatement.getPreparedStatement().addBatch();
                }
                unAssingPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
                    log.debug("{} permissions deleted from the role: {} in authorization store: {}.", removeList.size(),
                            roleId, authorizationStoreId);
                }
            }

            if (addList != null && !addList.isEmpty()) {

                NamedPreparedStatement assignPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE_BY_UNIQUE_ID));

                for (Permission permission : addList) {
                    assignPreparedStatement.setString("role_id", roleId);
                    assignPreparedStatement.setString("permission_id", permission.getPermissionId());
                    assignPreparedStatement.getPreparedStatement().addBatch();
                }

                assignPreparedStatement.getPreparedStatement().executeBatch();

                if (IS_DEBUG_ENABLED) {
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
