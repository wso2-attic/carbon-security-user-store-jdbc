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
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnector;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.security.userstore.jdbc.util.DatabaseUtil;
import org.wso2.carbon.security.userstore.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.security.userstore.jdbc.util.UnitOfWork;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.sql.DataSource;

/**
 * Identity store connector for JDBC based stores.
 * @since 1.0.0
 */
public class JDBCIdentityStoreConnector extends JDBCStoreConnector implements IdentityStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCIdentityStoreConnector.class);

    private DataSource dataSource;
    private IdentityStoreConnectorConfig identityStoreConfig;
    private String identityStoreId;

    @Override
    public void init(String storeId, IdentityStoreConnectorConfig identityStoreConfig) throws IdentityStoreException {

        Properties properties = identityStoreConfig.getStoreProperties();
        this.identityStoreId = storeId;
        this.identityStoreConfig = identityStoreConfig;

        try {
            dataSource = DatabaseUtil.getInstance()
                    .getDataSource(properties.getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new IdentityStoreException("Error occurred while initiating data source.", e);
        }

        loadQueries(properties);

        if (log.isDebugEnabled()) {
            log.debug("JDBC identity store with id: {} initialized successfully.", identityStoreId);
        }
    }

    @Override
    public String getIdentityStoreId() {
        return identityStoreId;
    }

    @Override
    public User.UserBuilder getUserBuilder(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreException {
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ATTRIBUTE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attributeName);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attributeValue);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new UserNotFoundException("User not found for the given user name in " + identityStoreId);
                }

                String userId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);

//                String credentialStoreId = resultSet.getString(DatabaseColumnNames.User.CREDENTIAL_STORE_ID);

                if (log.isDebugEnabled()) {
                    log.debug("User with user id: {} retrieved from identity store: {}.", userId, identityStoreId);
                }

                //TODO authorization store, claim manager and identity store are not set here
                return new User.UserBuilder().setUserId(userId).setTenantDomain(tenantDomain);
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user from database.", e);
        }
    }

    public User.UserBuilder getUser(String username) throws IdentityStoreException, UserNotFoundException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_USERNAME));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USERNAME, username);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new UserNotFoundException("User not found for the given user name in " + identityStoreId);
                }

                String userId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
//                String credentialStoreId = resultSet.getString(DatabaseColumnNames.User.CREDENTIAL_STORE_ID);

                if (log.isDebugEnabled()) {
                    log.debug("User with user id: {} retrieved from identity store: {}.", userId, identityStoreId);
                }

                //TODO authorization store, claim manager and identity store are not set here
                return new User.UserBuilder().setUserId(userId).setTenantDomain(tenantDomain);
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user from database.", e);
        }
    }

    @Override
    public User.UserBuilder getUserBuilder(Callback [] callbacks) throws IdentityStoreException, UserNotFoundException {

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                String username = ((NameCallback) callback).getName();
                return this.getUser(username);
            }
        }

        throw new IdentityStoreException("No name callback present in the callback array.");
    }

    @Override
    public int getUserCount() throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_COUNT_USERS));

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getInt(1);
                }
                return 0;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("An error occurred while getting user count.", e);
        }
    }

    public User.UserBuilder getUserFromId(String userId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ID));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    return null;
                }

//                String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
                String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
//                String credentialStoreId = resultSet.getString(DatabaseColumnNames.User.CREDENTIAL_STORE_ID);

                if (log.isDebugEnabled()) {
                    log.debug("User with user id: {} retrieved from identity store: {}.", userId, identityStoreId);
                }

                //TODO authorization store, claim manager and identity store are not set here
                return new User.UserBuilder().setUserId(userId).setTenantDomain(tenantDomain);
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user from database.", e);
        }
    }

    @Override
    public List<User.UserBuilder> getUserBuilderList(String attributeName, String filterPattern, int offset, int
            length) throws IdentityStoreException {
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        // We are using SQL filters. So replace the '*' with '%'.
        filterPattern = filterPattern.replace('*', '%');

        List<User.UserBuilder> userList = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement listUsersNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS_BY_ATTRIBUTE));
            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attributeName);
            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                    filterPattern);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, offset);

            try (ResultSet resultSet = listUsersNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
//                    String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
                    String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
//                    String credentialStoreId = resultSet.getString(DatabaseColumnNames.User.CREDENTIAL_STORE_ID);
                    //TODO authorization store, claim manager and identity store are not set here
                    userList.add(new User.UserBuilder().setUserId(userUniqueId).setTenantDomain(tenantDomain));
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} users retrieved from identity store: {}.", userList.size(), identityStoreId);
            }

            return userList;
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while listing users.", e);
        }
    }

    public List<User.UserBuilder> listUsers(String filterPattern, int offset, int length)
            throws IdentityStoreException {

        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        // We are using SQL filters. So replace the '*' with '%'.
        filterPattern = filterPattern.replace('*', '%');

        List<User.UserBuilder> userList = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement listUsersNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS));
            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USERNAME, filterPattern);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, offset);

            try (ResultSet resultSet = listUsersNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
//                    String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
                    String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
//                    String credentialStoreId = resultSet.getString(DatabaseColumnNames.User.CREDENTIAL_STORE_ID);
                    //TODO authorization store, claim manager and identity store are not set here
                    userList.add(new User.UserBuilder().setUserId(userUniqueId).setTenantDomain(tenantDomain));
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} users retrieved from identity store: {}.", userList.size(), identityStoreId);
            }

            return userList;
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while listing users.", e);
        }
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Attribute> userClaims = new ArrayList<>();

                while (resultSet.next()) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_NAME));
                    attribute.setAttributeValue(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_VALUE));
                    attribute.setIdentityStoreId(identityStoreId);
                    userClaims.add(attribute);
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} attributes of user: {} retrieved from identity store: {}.", userClaims.size(),
                            userId, identityStoreId);
                }

                return userClaims;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user claims.", e);
        }
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userId, List<String> attributeNames)
            throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            Map<String, Integer> repetitions = new HashMap<>();
            repetitions.put(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAMES, attributeNames.size());

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES_FROM_NAME),
                    repetitions);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAMES, attributeNames);
            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Attribute> userClaims = new ArrayList<>();

                while (resultSet.next()) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_NAME));
                    attribute.setAttributeValue(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_VALUE));
                    attribute.setIdentityStoreId(identityStoreId);
                    userClaims.add(attribute);
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} attributes of user: {} retrieved from identity store: {}.", userClaims.size(),
                            userId, identityStoreId);
                }

                return userClaims;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving user claims.", e);
        }
    }

    @Override
    public Group.GroupBuilder getGroupBuilder(String attributeName, String attributeValue) throws
            GroupNotFoundException, IdentityStoreException {
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ATTRIBUTE));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attributeName);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attributeValue);
            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new GroupNotFoundException("No group found for the given group name in " + identityStoreId);
                }

                String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);

                if (log.isDebugEnabled()) {
                    log.debug("Group with attribute {}: {} retrieved from identity store: {}.", attributeName,
                            attributeValue, identityStoreId);
                }

                return new Group.GroupBuilder().setGroupId(groupId).setTenantDomain(tenantDomain);
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving group.", e);
        }
    }


    public Group.GroupBuilder getGroup(String groupName) throws IdentityStoreException, GroupNotFoundException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_NAME));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_NAME, groupName);
            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new GroupNotFoundException("No group found for the given group name in " + identityStoreId);
                }

                String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);

                if (log.isDebugEnabled()) {
                    log.debug("Group with name: {} retrieved from identity store: {}.", groupName, identityStoreId);
                }

                return new Group.GroupBuilder().setGroupId(groupId).setTenantDomain(tenantDomain);
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving group.", e);
        }
    }

    @Override
    public int getGroupCount() throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_COUNT_GROUPS));

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getInt(1);
                }
                return 0;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("An error occurred while getting group count.", e);
        }
    }

    public Group.GroupBuilder getGroupById(String groupId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ID));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new IdentityStoreException("No group for given id.");
                }

//                String groupName = resultSet.getString(DatabaseColumnNames.Group.GROUP_NAME);
                String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);

                if (log.isDebugEnabled()) {
                    log.debug("Group with id: {} retrieved from identity store: {}.", groupId, identityStoreId);
                }

                //TODO authorization store and identity store are not set here
                return new Group.GroupBuilder().setGroupId(groupId).setTenantDomain(tenantDomain);
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving group.", e);
        }
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length)
            throws IdentityStoreException {

        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        // We are using SQL filters. So replace the '*' with '%'.
        filterPattern = filterPattern.replace('*', '%');

        List<Group.GroupBuilder> groups = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement listGroupsNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_GROUP));
            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_NAME, filterPattern);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, offset);

            try (ResultSet resultSet = listGroupsNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String groupUniqueId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
//                    String groupName = resultSet.getString(DatabaseColumnNames.Group.GROUP_NAME);
                    String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
                    groups.add(new Group.GroupBuilder().setGroupId(groupUniqueId).setTenantDomain(tenantDomain));
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} groups retrieved for filter pattern {} from identity store: {}.", groups.size(),
                        filterPattern, identityStoreId);
            }

            return groups;

        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving group list.");
        }
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_ATTRIBUTES));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Attribute> groupAttributes = new ArrayList<>();
                while (resultSet.next()) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(resultSet.getString(DatabaseColumnNames.GroupAttributes.ATTR_NAME));
                    attribute.setAttributeValue(resultSet.getString(DatabaseColumnNames.GroupAttributes.ATTR_VALUE));
                    attribute.setIdentityStoreId(identityStoreId);
                    groupAttributes.add(attribute);
                }

                return groupAttributes;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving attribute values of the group.", e);
        }
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames)
            throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            Map<String, Integer> repetitions = new HashMap<>();
            repetitions.put(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAMES, attributeNames.size());

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_ATTRIBUTES_FROM_NAME),
                    repetitions);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAMES, attributeNames);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                ArrayList<Attribute> groupAttributes = new ArrayList<>();
                while (resultSet.next()) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(resultSet.getString(DatabaseColumnNames.GroupAttributes.ATTR_NAME));
                    attribute.setAttributeValue(resultSet.getString(DatabaseColumnNames.GroupAttributes.ATTR_VALUE));
                    attribute.setIdentityStoreId(identityStoreId);
                    groupAttributes.add(attribute);
                }

                return groupAttributes;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving attribute values of the group.", e);
        }
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuildersOfUser(String userId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUPS_OF_USER));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Group.GroupBuilder> groupList = new ArrayList<>();
                while (resultSet.next()) {
//                    String groupName = resultSet.getString(DatabaseColumnNames.Group.GROUP_NAME);
                    String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                    String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
                    //TODO authorization store and identity store are not set here
                    Group.GroupBuilder group = new Group.GroupBuilder().setGroupId(groupId)
                            .setTenantDomain(tenantDomain);
                    groupList.add(group);
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} groups retrieved for user id {} from identity store: {}.", groupList.size(),
                            userId, identityStoreId);
                }

                return groupList;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving groups of user.", e);
        }
    }

    @Override
    public List<User.UserBuilder> getUserBuildersOfGroup(String groupId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USERS_OF_GROUP));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<User.UserBuilder> userList = new ArrayList<>();
                while (resultSet.next()) {
//                    String username = resultSet.getString(DatabaseColumnNames.User.USERNAME);
                    String userId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                    String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
//                    String credentialStoreId = resultSet.getString(DatabaseColumnNames.User.CREDENTIAL_STORE_ID);
                    //TODO authorization store, identity store and claim manager are not set here
                    User.UserBuilder user = new User.UserBuilder().setUserId(userId).setTenantDomain(tenantDomain);
                    userList.add(user);
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} users retrieved for group: {} from identity store: {}.", userList.size(), groupId,
                            identityStoreId);
                }

                return userList;
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while retrieving users of group.", e);
        }
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_IS_USER_IN_GROUP));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException e) {
            throw new IdentityStoreException("Error while checking users in group.", e);
        }
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreException {
        return false;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return identityStoreConfig;
    }

    /**
     * Get the maximum number of rows allowed to retrieve in a single query.
     * @return Max allowed number of rows.
     */
    private int getMaxRowRetrievalCount() {

        int length;

        String maxValue = identityStoreConfig.getStoreProperties().getProperty(ConnectorConstants.MAX_ROW_LIMIT);

        if (maxValue == null) {
            length = Integer.MAX_VALUE;
        } else {
            length = Integer.parseInt(maxValue);
        }

        return length;
    }
}
