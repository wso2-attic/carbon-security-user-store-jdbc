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
import org.wso2.carbon.identity.mgt.bean.Attribute;
import org.wso2.carbon.identity.mgt.bean.Group;
import org.wso2.carbon.identity.mgt.bean.User;
import org.wso2.carbon.identity.mgt.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.store.connector.IdentityStoreConnector;
import org.wso2.carbon.kernel.utils.StringUtils;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.security.userstore.jdbc.internal.ConnectorDataHolder;
import org.wso2.carbon.security.userstore.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.security.userstore.jdbc.util.UnitOfWork;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.sql.DataSource;

/**
 * Identity store connector for JDBC based stores.
 *
 * @since 1.0.0
 */
public class JDBCIdentityStoreConnector extends JDBCStoreConnector implements IdentityStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCIdentityStoreConnector.class);

    protected DataSource dataSource;
    protected IdentityStoreConnectorConfig identityStoreConfig;
    protected String identityStoreId;
    protected String connectorUserId;
    protected String connectorGroupId;

    @Override
    public void init(IdentityStoreConnectorConfig identityStoreConfig) throws IdentityStoreException {

        Properties properties = identityStoreConfig.getProperties();
        this.identityStoreId = identityStoreConfig.getConnectorId();
        this.identityStoreConfig = identityStoreConfig;

        try {
            dataSource = ConnectorDataHolder.getInstance()
                    .getDataSource(properties.getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new IdentityStoreException("Error occurred while initiating data source.", e);
        }

        loadQueries(properties);

        if (log.isDebugEnabled()) {
            log.debug("JDBC identity store with id: {} initialized successfully.", identityStoreId);
        }

        //TODO check whether this is okay to be a property
        connectorUserId = identityStoreConfig.getProperties().getProperty("connectorUserId");
        connectorGroupId = identityStoreConfig.getProperties().getProperty("connectorGroupId");
    }

    @Override
    public String getIdentityStoreConnectorId() {
        return identityStoreId;
    }

    @Override
    public String getConnectorUserId(String attributeName, String attributeValue) throws UserNotFoundException,
            IdentityStoreException {
        return connectorUserId;
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
            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                    attributeName);

            listUsersNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                    filterPattern);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listUsersNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, offset);

            try (ResultSet resultSet = listUsersNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                    userList.add(new User.UserBuilder().setUserId(userUniqueId));
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
    public List<User.UserBuilder> getAllUserBuilderList(String attributeName, String filterPattern) throws
            IdentityStoreException {
        return getUserBuilderList(attributeName, filterPattern, 0, -1);
    }

    @Override
    public List<Attribute> getUserAttributeValues(String userId) throws IdentityStoreException {

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
            throw new IdentityStoreException("Error occurred while retrieving user attributes.", e);
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
            throw new IdentityStoreException("Error occurred while retrieving user attributes.", e);
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
                    throw new GroupNotFoundException("Group not found for the given group name in " +
                            identityStoreId);
                }

                String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);

                if (log.isDebugEnabled()) {
                    log.debug("Group with attribute {}: {} retrieved from identity store: {}.", attributeName,
                            attributeValue, identityStoreId);
                }

                return new Group.GroupBuilder().setGroupId(groupId);
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

    @Override
    public String getConnectorGroupId(String attributeName, String attributeValue) throws GroupNotFoundException,
            IdentityStoreException {
        return null;
    }

    @Override
    public List<Group.GroupBuilder> getGroupBuilderList(String filterPattern, int offset, int length)
            throws IdentityStoreException {

        //TODO Check whether method is needed. If so need to change the implementation
        // Get the max allowed row count if the length is -1.
//        if (length == -1) {
//            length = getMaxRowRetrievalCount();
//        }
//
//        // We are using SQL filters. So replace the '*' with '%'.
//        filterPattern = filterPattern.replace('*', '%');
//
//        List<Group.GroupBuilder> groups = new ArrayList<>();
//
//        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {
//
//            NamedPreparedStatement listGroupsNamedPreparedStatement = new NamedPreparedStatement(
//                    unitOfWork.getConnection(),
//                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_GROUP));
//            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_NAME, filterPattern);
//            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
//            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, offset);
//
//            try (ResultSet resultSet = listGroupsNamedPreparedStatement.getPreparedStatement().executeQuery()) {
//
//                while (resultSet.next()) {
//                    String groupUniqueId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
////                    String groupName = resultSet.getString(DatabaseColumnNames.Group.GROUP_NAME);
//                    groups.add(new Group.GroupBuilder().setGroupId(groupUniqueId));
//                }
//            }
//
//            if (log.isDebugEnabled()) {
//                log.debug("{} groups retrieved for filter pattern {} from identity store: {}.", groups.size(),
//                        filterPattern, identityStoreId);
//            }
//
//            return groups;
//
//        } catch (SQLException e) {
//            throw new IdentityStoreException("Error occurred while retrieving group list.");
//        }
        return new ArrayList<>();
    }

    //TODO This should be added to the interface
    public List<Group.GroupBuilder> getGroupBuilderList(String attributeName, String filterPattern, int offset, int
            length) throws IdentityStoreException {

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
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_GROUP_BY_ATTRIBUTE));
            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME,
                    attributeName);
            listGroupsNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE,
                    filterPattern);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.LENGTH, length);
            listGroupsNamedPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.OFFSET, offset);

            try (ResultSet resultSet = listGroupsNamedPreparedStatement.getPreparedStatement().executeQuery()) {

                while (resultSet.next()) {
                    String groupUniqueId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                    groups.add(new Group.GroupBuilder().setGroupId(groupUniqueId));
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
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, userId);

            try (ResultSet resultSet = namedPreparedStatement.getPreparedStatement().executeQuery()) {

                List<Group.GroupBuilder> groupList = new ArrayList<>();
                while (resultSet.next()) {
                    String groupId = resultSet.getString(DatabaseColumnNames.Group.GROUP_UNIQUE_ID);
                    Group.GroupBuilder group = new Group.GroupBuilder().setGroupId(groupId);
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
                    String userId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                    User.UserBuilder user = new User.UserBuilder().setUserId(userId);
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

    @Override
    public Attribute addUser(List<Attribute> attributes) throws IdentityStoreException {

        Attribute primaryAttribute = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute)
                .findFirst()
                .orElse(null);

        if (primaryAttribute == null || StringUtils.isNullOrEmptyAfterTrim(primaryAttribute.getAttributeValue())) {
            throw new IdentityStoreException("Primary Attribute " + connectorUserId + " is not found among the " +
                    "attribute list");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER));
            addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    primaryAttribute.getAttributeValue());
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
                        primaryAttribute.getAttributeValue());
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while storing user.", e);
        }
        return primaryAttribute;
    }

    @Override
    public Map<String, String> addUsers(Map<String, List<Attribute>> attributes) throws IdentityStoreException {

        IdentityStoreException identityStoreException = new IdentityStoreException();
        Map<String, String> userIdsToReturn = new HashMap<>();
        attributes.entrySet().stream().forEach(entry -> {
            try {
                Attribute attribute = addUser(entry.getValue());
                userIdsToReturn.put(entry.getKey(), attribute.getAttributeValue());
            } catch (IdentityStoreException e) {
                identityStoreException.addSuppressed(e);
            }
        });

        if (identityStoreException.getSuppressed().length > 0) {
            throw identityStoreException;
        }
        return userIdsToReturn;
    }

    @Override
    public String updateUserAttributes(String userIdentifier, List<Attribute> attributes) throws
            IdentityStoreException {

        //PUT operation
        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        String userIdentifierNew = userIdentifier;

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            //Update the primary attribute of the connector
            if (!StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {
                NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                        .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                        .SQL_QUERY_UPDATE_USER));
                addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .USER_UNIQUE_ID_UPDATE, primaryAttributeValue);
                addUserNamedPreparedStatement.getPreparedStatement().executeUpdate();

                //If the primary attribute of the connector is also going to be updated, new value should be used for
                // the other queries.
                userIdentifierNew = primaryAttributeValue;
            }

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ALL_ATTRIBUTES_OF_USER));
            removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    userIdentifierNew);
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
                        userIdentifierNew);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while updating user.", e);
        }
        return userIdentifierNew;
    }

    @Override
    public String updateUserAttributes(String userIdentifier, List<Attribute> attributesToAdd,
                                       List<Attribute> attributesToRemove) throws IdentityStoreException {

        //PATCH operation
        String primaryAttributeToRemove = attributesToRemove.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        String primaryAttributeValue = attributesToAdd.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorUserId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        //If primary attribute is in the remove list, new value should be in the add list.
        if (!StringUtils.isNullOrEmptyAfterTrim(primaryAttributeToRemove) && StringUtils.isNullOrEmptyAfterTrim
                (primaryAttributeValue)) {
            throw new IdentityStoreException("Primary attribute of the connector cannot be removed");
        }

        String userIdentifierNew = userIdentifier;

        //Filter the attributes to add and update
        List<Attribute> currentAttributes = getUserAttributeValues(userIdentifier);
        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : currentAttributes) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }

        List<Attribute> filteredAttributesToAdd = new ArrayList<>();
        List<Attribute> filteredAttributesToUpdate = new ArrayList<>();

        for (Attribute attribute : attributesToAdd) {
            if (attributeMap.get(attribute.getAttributeName()) != null) {
                filteredAttributesToUpdate.add(attribute);
            } else {
                filteredAttributesToAdd.add(attribute);
            }
        }
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {


            //Update the primary attribute of the connector
            if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeToRemove) || !StringUtils.isNullOrEmptyAfterTrim
                    (primaryAttributeValue)) {
                NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                        .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                        .SQL_QUERY_UPDATE_USER));
                addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                        userIdentifier);
                addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .USER_UNIQUE_ID_UPDATE, primaryAttributeValue);
                addUserNamedPreparedStatement.getPreparedStatement().executeUpdate();

                //If the primary attribute of the connector is also going to be updated, new value should be used for
                // the other queries.
                userIdentifierNew = primaryAttributeValue;
            }

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ATTRIBUTE_OF_USER));
            for (Attribute attribute : attributesToRemove) {
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .ATTRIBUTE_NAME, attribute.getAttributeName());
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .USER_UNIQUE_ID, userIdentifierNew);
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
                        userIdentifierNew);
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
                        userIdentifierNew);
                updateNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            updateNamedPreparedStatement.getPreparedStatement().executeBatch();

            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while updating user.", e);
        }
        return userIdentifierNew;
    }

    @Override
    public void deleteUser(String userIdentifier) throws IdentityStoreException {
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, userIdentifier);
            namedPreparedStatement.getPreparedStatement().executeUpdate();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while deleting user.", e);
        }
    }

    @Override
    public void updateGroupsOfUser(String userIdentifier, List<String> groupIdentifiers) throws IdentityStoreException {

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
            throw new IdentityStoreException("Error occurred while updating groups of user.", e);
        }
    }

    @Override
    public void updateGroupsOfUser(String userIdentifier, List<String> groupIdentifiersToAdd,
                                   List<String> groupIdentifiersToRemove) throws IdentityStoreException {

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
            throw new IdentityStoreException("Error occurred while updating groups of user.", e);
        }
    }

    @Override
    public String addGroup(List<Attribute> attributes) throws IdentityStoreException {

        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorGroupId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {
            throw new IdentityStoreException("Primary Attribute " + connectorGroupId + " is not found among the " +
                    "attribute list");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addGroupNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP));
            addGroupNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                    primaryAttributeValue);
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
                        primaryAttributeValue);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while storing group.", e);
        }

        return primaryAttributeValue;
    }

    @Override
    public Map<String, String> addGroups(Map<String, List<Attribute>> attributes) throws IdentityStoreException {

        IdentityStoreException identityStoreException = new IdentityStoreException();
        Map<String, String> groupIdsToReturn = new HashMap<>();
        attributes.entrySet().stream().forEach(entry -> {
            try {
                String groupId = addGroup(entry.getValue());
                groupIdsToReturn.put(entry.getKey(), groupId);
            } catch (IdentityStoreException e) {
                identityStoreException.addSuppressed(e);
            }
        });

        if (identityStoreException.getSuppressed().length > 0) {
            throw identityStoreException;
        }
        return groupIdsToReturn;
    }

    @Override
    public String updateGroupAttributes(String groupIdentifier, List<Attribute> attributes) throws
            IdentityStoreException {
        //PUT operation
        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorGroupId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        String groupIdentifierNew = groupIdentifier;

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            //Update the primary attribute of the connector
            if (!StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {
                NamedPreparedStatement addGroupNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                        .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                        .SQL_QUERY_UPDATE_GROUP));
                addGroupNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                addGroupNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .GROUP_UNIQUE_ID_UPDATE, primaryAttributeValue);
                addGroupNamedPreparedStatement.getPreparedStatement().executeUpdate();

                //If the primary attribute of the connector is also going to be updated, new value should be used for
                // the other queries.
                groupIdentifierNew = primaryAttributeValue;
            }

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ALL_ATTRIBUTES_OF_GROUP));
            removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                    groupIdentifierNew);
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
                        groupIdentifierNew);
                namedPreparedStatement.getPreparedStatement().addBatch();
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while updating user.", e);
        }
        return groupIdentifierNew;
    }

    @Override
    public String updateGroupAttributes(String groupIdentifier, List<Attribute> attributesToAdd,
                                        List<Attribute> attributesToRemove) throws IdentityStoreException {
        //PATCH operation
        String primaryAttributeToRemove = attributesToRemove.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorGroupId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        String primaryAttributeValue = attributesToAdd.stream()
                .filter(attribute -> attribute.getAttributeName().equals(connectorGroupId))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        //If primary attribute is in the remove list, new value should be in the add list.
        if (!StringUtils.isNullOrEmptyAfterTrim(primaryAttributeToRemove) && StringUtils.isNullOrEmptyAfterTrim
                (primaryAttributeValue)) {
            throw new IdentityStoreException("Primary attribute of the connector cannot be removed");
        }

        String userIdentifierNew = groupIdentifier;

        //Filter the attributes to add and update
        List<Attribute> currentAttributes = getUserAttributeValues(groupIdentifier);
        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : currentAttributes) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }

        List<Attribute> filteredAttributesToAdd = new ArrayList<>();
        List<Attribute> filteredAttributesToUpdate = new ArrayList<>();

        for (Attribute attribute : attributesToAdd) {
            if (attributeMap.get(attribute.getAttributeName()) != null) {
                filteredAttributesToUpdate.add(attribute);
            } else {
                filteredAttributesToAdd.add(attribute);
            }
        }
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            //Update the primary attribute of the connector
            if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeToRemove) || !StringUtils.isNullOrEmptyAfterTrim
                    (primaryAttributeValue)) {
                NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                        .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                        .SQL_QUERY_UPDATE_GROUP));
                addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                        groupIdentifier);
                addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .GROUP_UNIQUE_ID_UPDATE, primaryAttributeValue);
                addUserNamedPreparedStatement.getPreparedStatement().executeUpdate();

                //If the primary attribute of the connector is also going to be updated, new value should be used for
                // the other queries.
                userIdentifierNew = primaryAttributeValue;
            }

            //Delete the existing attributes
            NamedPreparedStatement removeAttributesNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(ConnectorConstants.QueryTypes
                    .SQL_QUERY_REMOVE_ATTRIBUTE_OF_GROUP));
            for (Attribute attribute : attributesToRemove) {
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .ATTRIBUTE_NAME, attribute.getAttributeName());
                removeAttributesNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders
                        .GROUP_UNIQUE_ID, userIdentifierNew);
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
                        userIdentifierNew);
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
                        userIdentifierNew);
                updateNamedPreparedStatement.getPreparedStatement().addBatch();
            }
            updateNamedPreparedStatement.getPreparedStatement().executeBatch();

            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while updating user.", e);
        }
        return userIdentifierNew;
    }

    @Override
    public void deleteGroup(String groupIdentifier) throws IdentityStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP));
            namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID, groupIdentifier);
            namedPreparedStatement.getPreparedStatement().executeUpdate();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while deleting user.", e);
        }
    }

    @Override
    public void updateUsersOfGroup(String groupIdentifier, List<String> userIdentifiers) throws IdentityStoreException {

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
            throw new IdentityStoreException("Error occurred while updating groups of user.", e);
        }
    }

    @Override
    public void updateUsersOfGroup(String groupIdentifier, List<String> userIdentifiersToAdd,
                                   List<String> userIdentifiersToRemove) throws IdentityStoreException {

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
            throw new IdentityStoreException("Error occurred while updating groups of user.", e);
        }
    }

    /**
     * Get the maximum number of rows allowed to retrieve in a single query.
     *
     * @return Max allowed number of rows.
     */
    private int getMaxRowRetrievalCount() {

        int length;

        String maxValue = identityStoreConfig.getProperties().getProperty(ConnectorConstants.MAX_ROW_LIMIT);

        if (maxValue == null) {
            length = Integer.MAX_VALUE;
        } else {
            length = Integer.parseInt(maxValue);
        }

        return length;
    }
}
