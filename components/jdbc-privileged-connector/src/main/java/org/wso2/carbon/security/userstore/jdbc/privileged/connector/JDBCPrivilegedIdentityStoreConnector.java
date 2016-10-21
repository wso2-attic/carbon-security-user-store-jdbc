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

package org.wso2.carbon.security.userstore.jdbc.privileged.connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.user.mgt.store.connector.PrivilegedIdentityStoreConnector;
import org.wso2.carbon.kernel.utils.StringUtils;
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.userstore.jdbc.connector.JDBCIdentityStoreConnector;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.privileged.constant.PrivilegedConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.privileged.queries.PrivilegedMySQLFamilySQLQueryFactory;
import org.wso2.carbon.security.userstore.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.security.userstore.jdbc.util.UnitOfWork;

import java.sql.SQLException;
import java.util.List;
import java.util.Properties;

/**
 * Identity store connector for JDBC based stores.
 *
 * @since 1.0.0
 */
public class JDBCPrivilegedIdentityStoreConnector extends JDBCIdentityStoreConnector implements
        PrivilegedIdentityStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCPrivilegedIdentityStoreConnector.class);
    String primaryAttributeName;

    @Override
    public void init(String storeId, IdentityStoreConnectorConfig identityStoreConfig) throws IdentityStoreException {
        super.init(storeId, identityStoreConfig);
        primaryAttributeName = identityStoreConfig.getPrimaryAttributeName();
    }

    @Override
    public void addUser(List<Attribute> attributes) throws IdentityStoreException {

        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(primaryAttributeName))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {
            throw new IdentityStoreException("Primary Attribute " + primaryAttributeName + " is not found among the " +
                    "attribute list");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER));
            addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    primaryAttributeValue);
            addUserNamedPreparedStatement.getPreparedStatement().executeUpdate();

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(),
                    sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_CLAIMS));
            for (Attribute attribute : attributes) {
                if (!attribute.getAttributeName().equals(primaryAttributeName)) {
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                            .getAttributeName());
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                            .getAttributeValue());
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                            primaryAttributeValue);
                    namedPreparedStatement.getPreparedStatement().addBatch();
                }
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while storing user.", e);
        }

    }

    @Override
    public void addUsers(List<List<Attribute>> attributes) throws IdentityStoreException {
        IdentityStoreException identityStoreException = new IdentityStoreException();
        attributes.stream().forEach(attributes1 -> {
            try {
                addUser(attributes1);
            } catch (IdentityStoreException e) {
                identityStoreException.addSuppressed(e);
            }
        });

        if (identityStoreException.getSuppressed().length > 0) {
            throw identityStoreException;
        }
    }

    @Override
    public void updateUserAttributes(String userIdentifier, List<Attribute> attributes) throws IdentityStoreException {

        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(primaryAttributeName))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {
            throw new IdentityStoreException("Primary Attribute " + primaryAttributeName + " is not found among the " +
                    "attribute list");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addUserNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_USER));
            addUserNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    userIdentifier);
            addUserNamedPreparedStatement.setString(PrivilegedConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID_UPDATE,
                    primaryAttributeValue);
            addUserNamedPreparedStatement.getPreparedStatement().executeUpdate();

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(),
                    sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_CLAIMS));
            for (Attribute attribute : attributes) {
                if (!attribute.getAttributeName().equals(primaryAttributeName)) {
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                            .getAttributeName());
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                            .getAttributeValue());
                    namedPreparedStatement.getPreparedStatement().addBatch();
                }
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while updating user.", e);
        }
    }

    @Override
    public void updateUserAttributes(String s, List<Attribute> list, List<Attribute> list1) throws
            IdentityStoreException {

    }

    @Override
    public void deleteUser(String s) throws IdentityStoreException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list) throws IdentityStoreException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list, List<String> list1) throws IdentityStoreException {

    }

    @Override
    public void addGroup(List<Attribute> attributes) throws IdentityStoreException {

        //TODO Change the primaryAttribute to primary attribute of the group
        String primaryAttributeValue = attributes.stream()
                .filter(attribute -> attribute.getAttributeName().equals(primaryAttributeName))
                .map(attribute -> attribute.getAttributeValue())
                .findFirst()
                .orElse(null);

        if (StringUtils.isNullOrEmptyAfterTrim(primaryAttributeValue)) {
            throw new IdentityStoreException("Primary Attribute " + primaryAttributeName + " is not found among the " +
                    "attribute list");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addGroupNamedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(), sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP));
            addGroupNamedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                    primaryAttributeValue);
            addGroupNamedPreparedStatement.getPreparedStatement().executeUpdate();

            NamedPreparedStatement namedPreparedStatement = new NamedPreparedStatement(unitOfWork
                    .getConnection(),
                    sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP_CLAIMS));
            for (Attribute attribute : attributes) {
                if (!attribute.getAttributeName().equals(primaryAttributeName)) {
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_NAME, attribute
                            .getAttributeName());
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.ATTRIBUTE_VALUE, attribute
                            .getAttributeValue());
                    namedPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.GROUP_UNIQUE_ID,
                            primaryAttributeValue);
                    namedPreparedStatement.getPreparedStatement().addBatch();
                }
            }
            namedPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new IdentityStoreException("Error occurred while storing group.", e);
        }
    }

    @Override
    public void addGroups(List<List<Attribute>> attributes) throws IdentityStoreException {
        IdentityStoreException identityStoreException = new IdentityStoreException();
        attributes.stream().forEach(attributes1 -> {
            try {
                addGroup(attributes1);
            } catch (IdentityStoreException e) {
                identityStoreException.addSuppressed(e);
            }
        });

        if (identityStoreException.getSuppressed().length > 0) {
            throw identityStoreException;
        }
    }

    @Override
    public void updateGroupAttributes(String s, List<Attribute> list) throws IdentityStoreException {

    }

    @Override
    public void updateGroupAttributes(String s, List<Attribute> list, List<Attribute> list1) throws
            IdentityStoreException {

    }

    @Override
    public void deleteGroup(String s) throws IdentityStoreException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list) throws IdentityStoreException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list, List<String> list1) throws IdentityStoreException {

    }

    protected void loadQueries(Properties properties) {

        String databaseType = properties.getProperty(ConnectorConstants.DATABASE_TYPE);

        if (databaseType != null && (databaseType.equalsIgnoreCase("MySQL") || databaseType.equalsIgnoreCase("H2"))) {
            sqlQueries = new PrivilegedMySQLFamilySQLQueryFactory().getQueries();
            if (log.isDebugEnabled()) {
                log.debug("{} sql queries loaded for database type: {}.", sqlQueries.size(), databaseType);
            }
        } else {
            throw new StoreException("Invalid or unsupported database type specified in the configuration.");
        }

        // If there are matching queries in the properties, we have to override the default and replace with them.
        sqlQueries.keySet().stream()
                .filter(properties::containsKey)
                .forEach(key -> sqlQueries.put(key, properties.getProperty(key)));
    }
}
