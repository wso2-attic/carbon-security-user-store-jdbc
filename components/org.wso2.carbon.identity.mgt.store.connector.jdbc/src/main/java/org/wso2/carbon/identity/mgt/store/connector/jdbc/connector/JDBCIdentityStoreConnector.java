/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.mgt.store.connector.jdbc.connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.identity.mgt.connector.Attribute;
import org.wso2.carbon.identity.mgt.connector.IdentityStoreConnector;
import org.wso2.carbon.identity.mgt.connector.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.StoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.impl.util.IdentityUserMgtUtil;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.internal.ConnectorDataHolder;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.queries.MySQLFamilySQLQueryFactory;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.util.UnitOfWork;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.sql.DataSource;

/**
 * Connector for JDBC based identity stores.
 *
 * @since 1.0.0
 */
public class JDBCIdentityStoreConnector extends JDBCStoreConnector implements IdentityStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCIdentityStoreConnector.class);
    protected DataSource dataSource;
    protected IdentityStoreConnectorConfig identityStoreConfig;
    protected String identityStoreId;

    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConfig) throws IdentityStoreConnectorException {

        Map<String, String> properties = identityStoreConfig.getProperties();
        this.identityStoreId = identityStoreConfig.getConnectorId();
        this.identityStoreConfig = identityStoreConfig;

        try {
            dataSource = ConnectorDataHolder.getInstance()
                    .getDataSource(properties.get(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new IdentityStoreConnectorException("Error occurred while initiating data source.", e);
        }

        loadQueries(properties);

        if (log.isDebugEnabled()) {
            log.debug("JDBC identity store with id: {} initialized successfully.", identityStoreId);
        }

    }

    @Override
    public String getIdentityStoreConnectorId() {
        return identityStoreId;
    }

    @Override
    public String getConnectorUserId(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ATTRIBUTE));

            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attributeName);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attributeValue);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                } else {
                    throw new UserNotFoundException("User not found with the given attribute");
                }
            }
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("An error occurred while getting searching the user.", e);
        }
    }

    @Override
    public List<String> listConnectorUserIds(String attributeName, String attributeValue, int startIndex, int length)
            throws IdentityStoreConnectorException {

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        List<String> userList = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {
            NamedPreparedStatement listUsersNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS_BY_ATTRIBUTE));
            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                    attributeName);

            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                    attributeValue);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, startIndex);

            try (ResultSet resultSet = listUsersNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                    userList.add(userUniqueId);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} users retrieved from identity store: {}.", userList.size(), identityStoreId);
            }

            return userList;
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while listing users.", e);
        }
    }

    @Override
    public List<String> listConnectorUserIdsByPattern(String attributeName, String filterPattern, int startIndex, int
            length) throws IdentityStoreConnectorException {

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        // We are using SQL filters. So replace the '*' with '%'.
        filterPattern = filterPattern.replace('*', '%');

        List<String> userList = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement listUsersNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS_BY_ATTRIBUTE_PATTERN));
            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                    attributeName);

            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                    filterPattern);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, startIndex);

            try (ResultSet resultSet = listUsersNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                    userList.add(userUniqueId);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} users retrieved from identity store: {}.", userList.size(), identityStoreId);
            }

            return userList;
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while listing users.", e);
        }
    }

    @Override
    public int getUserCount() throws IdentityStoreConnectorException {

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
            throw new IdentityStoreConnectorException("An error occurred while getting user count.", e);
        }
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userId) throws IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Attribute> userAttributes = new ArrayList<>();

                while (resultSet.next()) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_NAME));
                    attribute.setAttributeValue(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_VALUE));
                    userAttributes.add(attribute);
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} attributes of user: {} retrieved from identity store: {}.", userAttributes.size(),
                            userId, identityStoreId);
                }

                return userAttributes;
            }
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving user attributes.", e);
        }
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userId, List<String> attributeNames)
            throws IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            Map<String, Integer> repetitions = new HashMap<>();
            repetitions.put(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAMES, attributeNames.size());

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES_FROM_NAME),
                    repetitions);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAMES, attributeNames);
            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Attribute> userAttributes = new ArrayList<>();

                while (resultSet.next()) {
                    Attribute attribute = new Attribute();
                    attribute.setAttributeName(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_NAME));
                    attribute.setAttributeValue(resultSet.getString(DatabaseColumnNames.UserAttributes.ATTR_VALUE));
                    userAttributes.add(attribute);
                }

                if (log.isDebugEnabled()) {
                    log.debug("{} attributes of user: {} retrieved from identity store: {}.", userAttributes.size(),
                            userId, identityStoreId);
                }

                return userAttributes;
            }
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving user attributes.", e);
        }
    }

    @Override
    public int getGroupCount() throws IdentityStoreConnectorException {

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
            throw new IdentityStoreConnectorException("An error occurred while getting group count.", e);
        }
    }

    @Override
    public String getConnectorGroupId(String attributeName, String attributeValue) throws GroupNotFoundException,
            IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ATTRIBUTE));

            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attributeName);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attributeValue);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                } else {
                    throw new GroupNotFoundException("User not found with the given attribute");
                }
            }
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("An error occurred while getting searching the group.", e);
        }
    }

    @Override
    public List<String> listConnectorGroupIds(String attributeName, String attributeValue, int startIndex, int length)
            throws IdentityStoreConnectorException {

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        List<String> groups = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement listGroupsNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_GROUP_BY_ATTRIBUTE));
            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                    attributeName);
            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                    attributeValue);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, startIndex);

            try (ResultSet resultSet = listGroupsNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String groupUniqueId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                    groups.add(groupUniqueId);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} groups retrieved for filter pattern {} from identity store: {}.", groups.size(),
                        attributeValue, identityStoreId);
            }

            return groups;

        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list.");
        }
    }

    @Override
    public List<String> listConnectorGroupIdsByPattern(String attributeName, String filterPattern, int startIndex, int
            length) throws IdentityStoreConnectorException {

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }
        // Get the max allowed row count if the length is -1.
        if (length == -1) {
            length = getMaxRowRetrievalCount();
        }

        // We are using SQL filters. So replace the '*' with '%'.
        filterPattern = filterPattern.replace('*', '%');

        List<String> groups = new ArrayList<>();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement listGroupsNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_GROUP_BY_ATTRIBUTE_PATTERN));
            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                    attributeName);
            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                    filterPattern);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, startIndex);

            try (ResultSet resultSet = listGroupsNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String groupUniqueId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                    groups.add(groupUniqueId);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("{} groups retrieved for filter pattern {} from identity store: {}.", groups.size(),
                        filterPattern, identityStoreId);
            }

            return groups;

        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving group list.");
        }
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId) throws IdentityStoreConnectorException {

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
                    groupAttributes.add(attribute);
                }

                return groupAttributes;
            }
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving attribute values of the group" +
                    ".", e);
        }
    }

    @Override
    public List<Attribute> getGroupAttributeValues(String groupId, List<String> attributeNames)
            throws IdentityStoreConnectorException {

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
                    groupAttributes.add(attribute);
                }

                return groupAttributes;
            }
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while retrieving attribute values of the group" +
                    ".", e);
        }
    }

    @Override
    public boolean isUserInGroup(String userId, String groupId) throws IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_IS_USER_IN_GROUP));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, userId);
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_ID, groupId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {
                return resultSet.next();
            }
        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error while checking users in group.", e);
        }
    }

    @Override
    public boolean isReadOnly() throws IdentityStoreConnectorException {
        return false;
    }

    @Override
    public IdentityStoreConnectorConfig getIdentityStoreConfig() {
        return identityStoreConfig;
    }

    @Override
    public List<String> getUsers(List<Attribute> attributes, int offset, int length)
            throws IdentityStoreConnectorException {

        List<String> userIdsToReturn = new ArrayList<>();
        Map<String, String> properties = identityStoreConfig.getProperties();
        String databaseType =  properties.get(ConnectorConstants.DATABASE_TYPE);
        String sqlQuerryForUserAttributes;

        if (databaseType != null && (databaseType.equalsIgnoreCase("MySQL") ||
                databaseType.equalsIgnoreCase("H2"))) {

            sqlQuerryForUserAttributes = new MySQLFamilySQLQueryFactory()
                    .getQuerryForUserIdFromMultipleAttributes(attributes, offset, length);

            if (log.isDebugEnabled()) {
                log.debug("{} sql queries loaded for database type: {}.", sqlQueries.size(), databaseType);
            }
        } else {
            throw new StoreException("Invalid or unsupported database type specified in the configuration.");
        }
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement getUsersNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(), sqlQuerryForUserAttributes);

            try (ResultSet resultSet = getUsersNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                    userIdsToReturn.add(userUniqueId);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("Users retrieved from identity store: {}.", userIdsToReturn.size());
            }

        } catch (SQLException e) {
            throw new IdentityStoreConnectorException("Error occurred while getting database connection.", e);
        }
        return userIdsToReturn;
    }

    @Override
    public String addUser(List<Attribute> attributes) throws IdentityStoreConnectorException {

        String connectorUniqueId = IdentityUserMgtUtil.generateUUID();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER));
            addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    connectorUniqueId);
            addUserNamedPreparedStatement.getPreparedStatement().executeUpdate();

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_ATTRIBUTES));
            for (Attribute attribute : attributes) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        connectorUniqueId);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while storing user.", e);
        }
        return connectorUniqueId;
    }

    @Override
    public Map<String, String> addUsers(Map<String, List<Attribute>> attributes) throws
            IdentityStoreConnectorException {

        IdentityStoreConnectorException identityStoreException = new IdentityStoreConnectorException();
        Map<String, String> userIdsToReturn = new HashMap<>();
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER));
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_ATTRIBUTES));
            attributes.entrySet().stream().forEach(entry -> {
                try {
                    String connectorUniqueId = IdentityUserMgtUtil.generateUUID();

                    try {
                        addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                                connectorUniqueId);
                        addUserNamedPreparedStatement.getPreparedStatement().addBatch();

                        for (Attribute attribute : entry.getValue()) {
                            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                                    attribute

                                    .getAttributeName());
                            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                                    attribute
                                            .getAttributeValue());
                            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                                    connectorUniqueId);
                            namedPreparedStatement.getPreparedStatement().addBatch();
                        }
                    } catch (SQLException e) {
                        throw new IdentityStoreConnectorException("Error occurred while storing user.", e);
                    }
                    userIdsToReturn.put(entry.getKey(), connectorUniqueId);
                } catch (IdentityStoreConnectorException e) {
                    identityStoreException.addSuppressed(e);
                }
            });
            addUserNamedPreparedStatement.getPreparedStatement().executeBatch();
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while getting database connection.", e);
        }

        if (identityStoreException.getSuppressed().length > 0) {
            throw identityStoreException;
        }
        return userIdsToReturn;
    }

    @Override
    public String updateUserAttributes(String userIdentifier, List<Attribute> attributes) throws
            IdentityStoreConnectorException {

        //PUT operation

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ALL_ATTRIBUTES_OF_USER));
            removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    userIdentifier);
            removeAttributesNamedPreparedStatement.getPreparedStatement().executeUpdate();

            //Add new user attributes
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_ATTRIBUTES));
            for (Attribute attribute : attributes) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating user.", e);
        }
        return userIdentifier;
    }

    @Override
    public String updateUserAttributes(String userIdentifier, List<Attribute> attributesToAdd,
                                       List<Attribute> attributesToRemove) throws IdentityStoreConnectorException {

        //PATCH operation

        // Fetch the existing attributes of the user
        List<Attribute> currentAttributes = getUserAttributeValues(userIdentifier);

        // Filter the attributes to add and update
        // If the same attribute is present in the database already, update the value.
        // If the same attribute is not present in the database, add the attribute.
        // Map has a list of already existing attributes of the user with the key "true".
        // Map has a list of new attributes of the user with the key "false".
        Map<Boolean, List<Attribute>> attributeFilteredMap = attributesToAdd.stream()
                .collect(Collectors.partitioningBy(a -> currentAttributes.parallelStream().anyMatch(ca -> ca
                        .getAttributeName().equals(a.getAttributeName()))));

        List<Attribute> filteredAttributesToAdd = attributeFilteredMap.get(false);
        List<Attribute> filteredAttributesToUpdate = attributeFilteredMap.get(true);

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ATTRIBUTE_OF_USER));
            for (Attribute attribute : attributesToRemove) {
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .ATTRIBUTE_NAME, attribute.getAttributeName());
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .USER_UNIQUE_ID, userIdentifier);
                removeAttributesNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            removeAttributesNamedPreparedStatement.getPreparedStatement().executeBatch();

            //Add new user attributes
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_ATTRIBUTES));
            for (Attribute attribute : filteredAttributesToAdd) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();

            //Update user attributes
            NamedPreparedStatement updateNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_USER_ATTRIBUTES));
            for (Attribute attribute : filteredAttributesToUpdate) {
                updateNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                updateNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                updateNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                updateNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            updateNamedPreparedStatement.getPreparedStatement().executeBatch();

            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating user.", e);
        }
        return userIdentifier;
    }

    @Override
    public void deleteUser(String userIdentifier) throws IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, userIdentifier);
            namedPreparedStatement.getPreparedStatement().executeUpdate();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while deleting user.", e);
        }
    }

    @Override
    public void updateGroupsOfUser(String userIdentifier, List<String> groupIdentifiers) throws
            IdentityStoreConnectorException {

        //PUT operation
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            //remove already existing groups
            NamedPreparedStatement deleteNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ALL_GROUPS_OF_USER));
            deleteNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, userIdentifier);
            deleteNamedPreparedStatement.getPreparedStatement().executeUpdate();

            //add new groups
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUP));
            for (String groupIdentifier : groupIdentifiers) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating groups of user.", e);
        }
    }

    @Override
    public void updateGroupsOfUser(String userIdentifier, List<String> groupIdentifiersToAdd,
                                   List<String> groupIdentifiersToRemove) throws IdentityStoreConnectorException {

        //PATCH operation
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            //remove already existing groups
            NamedPreparedStatement deleteNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_GROUP_OF_USER));
            for (String groupIdentifier : groupIdentifiersToRemove) {
                deleteNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                deleteNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                deleteNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            deleteNamedPreparedStatement.getPreparedStatement().executeBatch();

            //add new groups
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUP));
            for (String groupIdentifier : groupIdentifiersToAdd) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating groups of user.", e);
        }
    }

    @Override
    public String addGroup(List<Attribute> attributes) throws IdentityStoreConnectorException {

        String connectorUniqueId = IdentityUserMgtUtil.generateUUID();

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addGroupNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP));
            addGroupNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                    connectorUniqueId);
            addGroupNamedPreparedStatement.getPreparedStatement().executeUpdate();

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP_ATTRIBUTES));
            for (Attribute attribute : attributes) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        connectorUniqueId);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while storing group.", e);
        }

        return connectorUniqueId;
    }

    @Override
    public Map<String, String> addGroups(Map<String, List<Attribute>> attributes) throws
            IdentityStoreConnectorException {

        IdentityStoreConnectorException identityStoreException = new IdentityStoreConnectorException();
        Map<String, String> groupIdsToReturn = new HashMap<>();
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addGroupNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP));
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP_ATTRIBUTES));
            attributes.entrySet().stream().forEach(entry -> {
                try {
                    String connectorUniqueId = IdentityUserMgtUtil.generateUUID();
                    try {

                        addGroupNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                                connectorUniqueId);
                        addGroupNamedPreparedStatement.getPreparedStatement().addBatch();

                        for (Attribute attribute : entry.getValue()) {
                            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                                    attribute.getAttributeName());
                            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                                    attribute
                                            .getAttributeValue());
                            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                                    connectorUniqueId);
                            namedPreparedStatement.getPreparedStatement().addBatch();
                        }
                    } catch (SQLException e) {
                        throw new IdentityStoreConnectorException("Error occurred while storing group.", e);
                    }
                    groupIdsToReturn.put(entry.getKey(), connectorUniqueId);
                } catch (IdentityStoreConnectorException e) {
                    identityStoreException.addSuppressed(e);
                }
            });
            addGroupNamedPreparedStatement.getPreparedStatement().executeBatch();
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while getting database connection.", e);
        }

        if (identityStoreException.getSuppressed().length > 0) {
            throw identityStoreException;
        }
        return groupIdsToReturn;
    }

    @Override
    public String updateGroupAttributes(String groupIdentifier, List<Attribute> attributes) throws
            IdentityStoreConnectorException {

        //PUT operation

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ALL_ATTRIBUTES_OF_GROUP));
            removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                    groupIdentifier);
            removeAttributesNamedPreparedStatement.getPreparedStatement().executeUpdate();

            //Add new group attributes
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP_ATTRIBUTES));
            for (Attribute attribute : attributes) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating user.", e);
        }
        return groupIdentifier;
    }

    @Override
    public String updateGroupAttributes(String groupIdentifier, List<Attribute> attributesToAdd,
                                        List<Attribute> attributesToRemove) throws IdentityStoreConnectorException {
        //PATCH operation

        // Fetch the existing attributes of the user
        List<Attribute> currentAttributes = getUserAttributeValues(groupIdentifier);

        // Filter the attributes to add and update
        // If the same attribute is present in the database already, update the value.
        // If the same attribute is not present in the database, add the attribute.
        // Map has a list of already existing attributes of the user with the key "true".
        // Map has a list of new attributes of the user with the key "false".
        Map<Boolean, List<Attribute>> attributeFilteredMap = attributesToAdd.stream()
                .collect(Collectors.partitioningBy(a -> currentAttributes.parallelStream().anyMatch(ca -> ca
                        .getAttributeName().equals(a.getAttributeName()))));

        List<Attribute> filteredAttributesToAdd = attributeFilteredMap.get(false);
        List<Attribute> filteredAttributesToUpdate = attributeFilteredMap.get(true);

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ATTRIBUTE_OF_GROUP));
            for (Attribute attribute : attributesToRemove) {
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .ATTRIBUTE_NAME, attribute.getAttributeName());
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .GROUP_UNIQUE_ID, groupIdentifier);
                removeAttributesNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            removeAttributesNamedPreparedStatement.getPreparedStatement().executeBatch();

            //Add new group attributes
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP_ATTRIBUTES));
            for (Attribute attribute : filteredAttributesToAdd) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();

            //Update group attributes
            NamedPreparedStatement updateNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_GROUP_ATTRIBUTES));
            for (Attribute attribute : filteredAttributesToUpdate) {
                updateNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                        .getAttributeName());
                updateNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                        .getAttributeValue());
                updateNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                updateNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            updateNamedPreparedStatement.getPreparedStatement().executeBatch();

            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating user.", e);
        }
        return groupIdentifier;
    }

    @Override
    public void deleteGroup(String groupIdentifier) throws IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID, groupIdentifier);
            namedPreparedStatement.getPreparedStatement().executeUpdate();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while deleting user.", e);
        }
    }

    @Override
    public void updateUsersOfGroup(String groupIdentifier, List<String> userIdentifiers) throws
            IdentityStoreConnectorException {

        //PUT operation
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            //remove already existing users
            NamedPreparedStatement deleteNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ALL_USERS_OF_GROUP));
            deleteNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID, groupIdentifier);
            deleteNamedPreparedStatement.getPreparedStatement().executeUpdate();

            //add new users
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUP));
            for (String userIdentifier : userIdentifiers) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating groups of user.", e);
        }
    }

    @Override
    public void updateUsersOfGroup(String groupIdentifier, List<String> userIdentifiersToAdd,
                                   List<String> userIdentifiersToRemove) throws IdentityStoreConnectorException {

        //PATCH operation
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            //remove already existing groups
            NamedPreparedStatement deleteNamedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_GROUP_OF_USER));
            for (String userIdentifier : userIdentifiersToRemove) {
                deleteNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                deleteNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                deleteNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            deleteNamedPreparedStatement.getPreparedStatement().executeBatch();

            //add new groups
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUP));
            for (String userIdentifier : userIdentifiersToAdd) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred while updating groups of user.", e);
        }
    }

    @Override
    public void removeAddedUsersInAFailure(List<String> connectorUserIds) throws IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER));
            for (String connectorUserId : connectorUserIds) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, connectorUserId);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred remove added users in failure.", e);
        }
    }

    @Override
    public void removeAddedGroupsInAFailure(List<String> connectorGroupIds) throws IdentityStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP));
            for (String connectorGroupId : connectorGroupIds) {
                namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID, connectorGroupId);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();

        } catch (SQLException e) {
            UnitOfWork.rollbackTransaction(dataSource);
            throw new IdentityStoreConnectorException("Error occurred remove added users in failure.", e);
        }
    }

    /**
     * Get the maximum number of rows allowed to retrieve in a single query.
     *
     * @return Max allowed number of rows.
     */
    private int getMaxRowRetrievalCount() {

        int length;

        String maxValue = identityStoreConfig.getProperties().get(ConnectorConstants.MAX_ROW_LIMIT);

        if (maxValue == null) {
            length = Integer.MAX_VALUE;
        } else {
            length = Integer.parseInt(maxValue);
        }

        return length;
    }
}
