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
import org.wso2.carbon.identity.mgt.IdentityCallback;
import org.wso2.carbon.identity.mgt.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.constant.UserCoreConstants;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreException;
import org.wso2.carbon.identity.mgt.store.connector.CredentialStoreConnector;
import org.wso2.carbon.identity.mgt.util.PasswordHandler;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.security.userstore.jdbc.internal.ConnectorDataHolder;
import org.wso2.carbon.security.userstore.jdbc.util.DefaultPasswordHandler;
import org.wso2.carbon.security.userstore.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.security.userstore.jdbc.util.UnitOfWork;

import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.sql.DataSource;

/**
 * JDBC connector for the credential store.
 *
 * @since 1.0.0
 */
public class JDBCCredentialStoreConnector extends JDBCStoreConnector implements CredentialStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCCredentialStoreConnector.class);

    private String credentialStoreId;
    private CredentialStoreConnectorConfig credentialStoreConfig;
    private DataSource dataSource;

    @Override
    public void init(CredentialStoreConnectorConfig configuration) throws CredentialStoreException {

        Properties properties = configuration.getProperties();
        this.credentialStoreConfig = configuration;
        this.credentialStoreId = configuration.getConnectorId();

        try {
            this.dataSource = ConnectorDataHolder.getInstance().getDataSource(properties
                    .getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new CredentialStoreException("Error while setting the data source.", e);
        }

        loadQueries(properties);

        if (log.isDebugEnabled()) {
            log.debug("JDBC credential store with id {} initialized successfully.", credentialStoreId);
        }
    }

    @Override
    public String getCredentialStoreConnectorId() {
        return credentialStoreId;
    }


    @Override
    public void authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {

        Map<String, String> userData = null;
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            } else if (callback instanceof IdentityCallback) {
                userData = (Map<String, String>) ((IdentityCallback) callback).getContent();
            }
        }

        if (userData == null || password == null || userData.isEmpty()) {
            throw new AuthenticationFailure("Data required for authentication is missing.");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            String hashedPassword = hashPassword(userData.get(UserCoreConstants.USER_ID), password, unitOfWork);

            NamedPreparedStatement comparePasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_COMPARE_PASSWORD_HASH));

            comparePasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.HASHED_PASSWORD,
                    hashedPassword);
            comparePasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID,
                    userData.get(UserCoreConstants.USER_ID));

            try (ResultSet resultSet = comparePasswordPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new AuthenticationFailure("Invalid username or password");
                }
            }
        } catch (SQLException | NoSuchAlgorithmException e) {
            throw new CredentialStoreException("Exception occurred while authenticating the user", e);
        }
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {

        boolean carbonCallbackPresent = false;
        boolean passwordCallbackPresent = false;

        for (Callback callback : callbacks) {
            if (callback instanceof IdentityCallback) {
                carbonCallbackPresent = true;
            }
            if (callback instanceof PasswordCallback) {
                passwordCallbackPresent = true;
            }
        }

        return carbonCallbackPresent && passwordCallbackPresent;
    }

    @Override
    public CredentialStoreConnectorConfig getCredentialStoreConfig() {
        return credentialStoreConfig;
    }

    @Override
    public void updateCredential(Callback[] callbacks) throws CredentialStoreException {
        Map<String, String> userData = null;
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof IdentityCallback) {
                userData = (Map<String, String>) ((IdentityCallback) callback).getContent();
            } else if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        updateCredential(userData.get(UserCoreConstants.USER_ID), password);
    }

    @Override
    public void updateCredential(String username, Callback[] callbacks) throws CredentialStoreException {
        char[] password = null;
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        updateCredential(username, password);
    }

    @Override
    public void addCredential(Callback[] callbacks) throws CredentialStoreException {
        Map<String, String> userData = null;
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof IdentityCallback) {
                userData = (Map<String, String>) ((IdentityCallback) callback).getContent();
            } else if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if (userData == null || userData.isEmpty()) {
            throw new CredentialStoreException("Data required for authentication is missing.");
        }

        addCredential(userData.get(UserCoreConstants.USER_ID), password);
    }

    @Override
    public void addCredential(String username, Callback[] callbacks) throws CredentialStoreException {

        char[] password = null;
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if (password == null) {
            throw new CredentialStoreException("Data required for authentication is missing.");
        }
        addCredential(username, password);
    }

    @Override
    public void deleteCredential(String username) throws CredentialStoreException {
        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement deleteCredentialPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_CREDENTIAL));

            deleteCredentialPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    username);

            deleteCredentialPreparedStatement.getPreparedStatement().executeUpdate();

            NamedPreparedStatement deletePasswordInfoPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_PASSWORD_INFO));

            deletePasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    username);

            deletePasswordInfoPreparedStatement.getPreparedStatement().executeUpdate();

        } catch (SQLException e) {
            throw new CredentialStoreException("Exception occurred while deleting the credential", e);
        }
    }

    private void addCredential(String username, char[] password) throws CredentialStoreException {

        String hashAlgo;
        int iterationCount;
        int keyLength;
        hashAlgo = credentialStoreConfig.getProperties().getProperty(ConnectorConstants.HASH_ALGO);
        if (hashAlgo == null) {
            hashAlgo = "SHA256";
        }
        Object iterationCountObj = credentialStoreConfig.getProperties().get(ConnectorConstants.ITERATION_COUNT);
        if (iterationCountObj != null) {
            iterationCount = (Integer) iterationCountObj;
        } else {
            iterationCount = 4096;
        }
        Object keyLengthObj = credentialStoreConfig.getProperties().get(ConnectorConstants.KEY_LENGTH);
        if (keyLengthObj != null) {
            keyLength = (Integer) keyLengthObj;
        } else {
            keyLength = 256;
        }

        //TODO is there another way to generate the salt
        String salt = UUID.randomUUID().toString();

        // Get a password handler if there is a one. Otherwise use the default one.
        PasswordHandler passwordHandler = ConnectorDataHolder.getInstance().getPasswordHandler(credentialStoreConfig
                .getProperties().getProperty(UserCoreConstants.PASSWORD_HANDLER_NAME));

        if (passwordHandler == null) {
            passwordHandler = new DefaultPasswordHandler();
            if (log.isDebugEnabled()) {
                log.debug("No password handler present. Using the default password handler.");
            }
        }

        passwordHandler.setIterationCount(iterationCount);
        passwordHandler.setKeyLength(keyLength);

        String hashedPassword;
        try {
            hashedPassword = passwordHandler.hashPassword(password, salt, hashAlgo);
        } catch (NoSuchAlgorithmException e) {
            throw new CredentialStoreException("Error while hashing the password.", e);
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {
            //Store password info.
            NamedPreparedStatement addPasswordInfoPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PASSWORD_INFO));
            addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD_SALT, salt);
            addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.HASH_ALGO, hashAlgo);
            addPasswordInfoPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.ITERATION_COUNT, iterationCount);
            addPasswordInfoPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.KEY_LENGTH, keyLength);
            addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            addPasswordInfoPreparedStatement.getPreparedStatement().executeUpdate();

            //Store password.
            NamedPreparedStatement addPasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_CREDENTIAL));
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD, hashedPassword);
            addPasswordPreparedStatement.getPreparedStatement().executeUpdate();
        } catch (SQLException e) {
            throw new CredentialStoreException("Error while storing user credential.", e);
        }
    }

    private void updateCredential(String username, char[] password) throws CredentialStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            String hashedPassword = hashPassword(username, password, unitOfWork);

            //Update password.
            NamedPreparedStatement addPasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_CREDENTIAL));
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD, hashedPassword);
            addPasswordPreparedStatement.getPreparedStatement().executeUpdate();
        } catch (SQLException | NoSuchAlgorithmException e) {
            throw new CredentialStoreException("Error while updating the password.", e);
        }
    }

    private String hashPassword(String username, char[] password, UnitOfWork unitOfWork) throws SQLException,
            CredentialStoreException, NoSuchAlgorithmException {
        NamedPreparedStatement getPasswordInfoPreparedStatement = new NamedPreparedStatement(
                unitOfWork.getConnection(),
                sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_INFO));
        getPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, username);

        String hashAlgo;
        String salt;
        int iterationCount;
        int keyLength;

        try (ResultSet resultSet = getPasswordInfoPreparedStatement.getPreparedStatement().executeQuery()) {

            if (!resultSet.next()) {
                throw new CredentialStoreException("Unable to retrieve password information.");
            }

            hashAlgo = resultSet.getString(DatabaseColumnNames.PasswordInfo.HASH_ALGO);
            salt = resultSet.getString(DatabaseColumnNames.PasswordInfo.PASSWORD_SALT);
            iterationCount = resultSet.getInt(DatabaseColumnNames.PasswordInfo.ITERATION_COUNT);
            keyLength = resultSet.getInt(DatabaseColumnNames.PasswordInfo.KEY_LENGTH);
        }

        // Get a password handler if there is a one. Otherwise use the default one.
        PasswordHandler passwordHandler = ConnectorDataHolder.getInstance().getPasswordHandler(credentialStoreConfig
                .getProperties().getProperty(UserCoreConstants.PASSWORD_HANDLER_NAME));

        if (passwordHandler == null) {
            passwordHandler = new DefaultPasswordHandler();
            if (log.isDebugEnabled()) {
                log.debug("No password handler present. Using the default password handler.");
            }
        }

        passwordHandler.setIterationCount(iterationCount);
        passwordHandler.setKeyLength(keyLength);

        return passwordHandler.hashPassword(password, salt, hashAlgo);
    }

}
