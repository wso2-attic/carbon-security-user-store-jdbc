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
import org.wso2.carbon.security.user.core.bean.Permission;
import org.wso2.carbon.security.user.core.bean.Role;
import org.wso2.carbon.security.user.core.config.AuthorizationStoreConfig;
import org.wso2.carbon.security.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.user.core.store.connector.AuthorizationStoreConnector;
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

    private DataSource dataSource;

    public void init(AuthorizationStoreConfig authorizationStoreConfig) throws AuthorizationStoreException {

        Properties properties = authorizationStoreConfig.getStoreProperties();
        loadQueries(properties.getProperty(ConnectorConstants.DATABASE_TYPE));

        try {
            this.dataSource = DatabaseUtil.getInstance().getDataSource(properties
                    .getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new AuthorizationStoreException("Error while setting the data source.", e);
        }

        if (log.isDebugEnabled()) {
            log.debug("JDBC authorization store connector initialized.");
        }
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
                return new Role.RoleBuilder(roleName, roleId);
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving the role.", e);
        }
    }

    @Override
    public Permission getPermission(String permissionId) {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> listRoles(String attribute, String filter) {
        return null;
    }

    @Override
    public List<Permission> listPermissions(String attribute, String filter) {
        return null;
    }

    @Override
    public List<Role.RoleBuilder> getRolesForUser(String userId) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_USER));
            namedPreparedStatement.setString("user_id", userId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Role.RoleBuilder> roles = new ArrayList<>();
                while (resultSet.next()) {
                    String roleName = resultSet.getString(DatabaseColumnNames.Role.ROLE_NAME);
                    String roleUniqueId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);
                    roles.add(new Role.RoleBuilder(roleName, roleUniqueId));
                }
                return roles;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving roles for user.", e);
        }
    }

    @Override
    public List<Role.RoleBuilder> getRolesForGroup(String groupId) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_GROUP));
            namedPreparedStatement.setString("group_id", groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Role.RoleBuilder> roles = new ArrayList<>();

                while (resultSet.next()) {
                    String roleId = resultSet.getString(DatabaseColumnNames.Role.ROLE_UNIQUE_ID);
                    String roleName = resultSet.getString(DatabaseColumnNames.Role.ROLE_NAME);
                    roles.add(new Role.RoleBuilder(roleName, roleId));
                }
                return roles;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving the roles of group", e);
        }
    }

    @Override
    public List<Permission> getPermissionsForRole(String roleId) throws AuthorizationStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSIONS_FOR_ROLE));
            namedPreparedStatement.setString("role_id", roleId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Permission> permissions = new ArrayList<>();
                while (resultSet.next()) {
                    String resourceId = resultSet.getString(DatabaseColumnNames.Permission.RESOURCE_ID);
                    String action = resultSet.getString(DatabaseColumnNames.Permission.ACTION);
                    permissions.add(new Permission(resourceId, action));
                }
                return permissions;
            }
        } catch (SQLException e) {
            throw new AuthorizationStoreException("An error occurred while retrieving permissions for role", e);
        }
    }

    @Override
    public Permission addNewPermission(String s, String s1) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public Role.RoleBuilder addNewRole(String s, List<Permission> list) throws AuthorizationStoreException {
        return null;
    }

    @Override
    public void assignUserRole(String userId, String roleName) throws AuthorizationStoreException {
    }

    @Override
    public void addRolePermission(String roleName, String permissionName) throws AuthorizationStoreException {
    }
}
