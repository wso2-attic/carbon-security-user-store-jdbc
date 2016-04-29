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
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
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
import java.util.stream.Collectors;
import javax.sql.DataSource;

/**
 * JDBC connector for authorization store.
 * @since 1.0.0
 */
public class JDBCAuthorizationConnector extends JDBCStoreConnector implements AuthorizationStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCAuthorizationConnector.class);

    private String authorizationStoreId;
    private AuthorizationStoreConfig authorizationStoreConfig;
    private DataSource dataSource;

    public void init(String storeId, AuthorizationStoreConfig authorizationStoreConfig)
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

        if (log.isDebugEnabled()) {
            log.debug("JDBC authorization store connector initialized.");
        }
    }

    @Override
    public String getAuthorizationStoreId() {
        return authorizationStoreId;
    }

    @Override
    public Role.RoleBuilder getRole(String roleName) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLE));
            namedPreparedStatement.setString("role_name", roleName);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new AuthorizationStoreException("No role found for the given name.");
                }

                String roleId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);
                return new Role.RoleBuilder().setRoleName(roleName).setRoleId(roleId)
                        .setAuthorizationStoreId(authorizationStoreId);
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving the role.", e);
        }
    }

    @Override
    public Permission.PermissionBuilder getPermission(String permissionId) throws AuthorizationStoreException {
        return null;
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
                return roles;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving the roles of group", e);
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

                return permissionBuilders;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving permissions for role", e);
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

            return new Permission.PermissionBuilder(resourceId, action,
                    permissionId, authorizationStoreId);
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while adding the permission.", e);
        }
    }

    @Override
    public Role.RoleBuilder addRole(String roleName, List<Permission> permissions) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            List<Long> permissionIds = new ArrayList<>();
            if (!permissions.isEmpty()) {
                NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                        sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSION_IDS));
                namedPreparedStatement.setString("actions", permissions
                        .stream()
                        .map(Permission::getAction)
                        .collect(Collectors.toList()));
                namedPreparedStatement.setString("resource_ids", permissions
                        .stream()
                        .map(Permission::getResourceId)
                        .collect(Collectors.toList()));
                try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                    while (resultSet.next()) {
                        permissionIds.add(resultSet.getLong(DatabaseColumnNames.Permission.ID));
                    }
                }
            }

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

            NamedPreparedStatement addRolePermissionPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLE_PERMISSION));

            for (long permissionId : permissionIds) {
                addRolePermissionPreparedStatement.setLong("role_id", roleId);
                addRolePermissionPreparedStatement.setLong("permission_id", permissionId);
                addRolePermissionPreparedStatement.getPreparedStatement().addBatch();
            }

            addRolePermissionPreparedStatement.getPreparedStatement().executeBatch();

            return new Role.RoleBuilder().setAuthorizationStoreId(authorizationStoreId).setRoleName(roleName)
                    .setRoleId(roleUniqueId);

        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while adding the role.", e);
        }
    }

    @Override
    public void assignUserRole(String userId, String roleName) throws AuthorizationStoreException {
    }

    @Override
    public void addRolePermission(String roleName, String permissionName) throws AuthorizationStoreException {
    }

    @Override
    public AuthorizationStoreConfig getAuthorizationStoreConfig() {
        return authorizationStoreConfig;
    }

    @Override
    public boolean isUserInRole(String userId, String identityStoreId, String roleName) {
        return false;
    }

    @Override
    public boolean isGroupInRole(String groupId, String identityStoreId, String roleName) {
        return false;
    }

    @Override
    public List<User.UserBuilder> getUsersOfRole(String s) {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupsOfRole(String s) {
        return null;
    }

    @Override
    public void deleteRole(String s) {
    }

    @Override
    public void deletePermission(String s) {
    }

    @Override
    public void updateRolesInUser(String userId, String identityStoreId, List<Role> list) {
    }
}
