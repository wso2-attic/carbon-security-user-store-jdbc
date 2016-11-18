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
import org.wso2.carbon.identity.mgt.util.IdentityUserMgtUtil;
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

            NamedPreparedStatement comparePasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_DATA));

            comparePasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID,
                    userData.get(UserCoreConstants.USER_ID));

            try (ResultSet resultSet = comparePasswordPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new AuthenticationFailure("Invalid username or password");
                } else {
                    String hashAlgo = resultSet.getString(DatabaseColumnNames.PasswordInfo.HASH_ALGO);
                    int iterationCount = resultSet.getInt(DatabaseColumnNames.PasswordInfo.ITERATION_COUNT);
                    int keyLength = resultSet.getInt(DatabaseColumnNames.PasswordInfo.KEY_LENGTH);
                    String salt = resultSet.getString(DatabaseColumnNames.PasswordInfo.PASSWORD_SALT);
                    String storedPassword = resultSet.getString(DatabaseColumnNames.Password.PASSWORD);
                    String hashedPassword = hashPassword(password, hashAlgo, salt, iterationCount, keyLength);

                    if ((storedPassword == null) || (!storedPassword.equals(hashedPassword))) {
                        throw new AuthenticationFailure("Invalid username or password");
                    }
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
    public String addCredential(Callback[] callbacks) throws CredentialStoreException {
        Map<String, String> userData = null;
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof IdentityCallback) {
                userData = (Map<String, String>) ((IdentityCallback) callback).getContent();
            } else if (callback instanceof PasswordCallback) {
                if (password == null) {
                    password = ((PasswordCallback) callback).getPassword();
                } else {
                    throw new CredentialStoreException("Multiple passwords found");
                }
            }
        }

        String username;

        if (userData == null || userData.isEmpty()) {
            username = IdentityUserMgtUtil.generateUUID();
        } else {
            username = userData.get(UserCoreConstants.USER_ID);
        }

        addCredential(username, password);
        return username;

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

        } catch (SQLException e) {
            throw new CredentialStoreException("Exception occurred while deleting the credential", e);
        }
    }

    private void addCredential(String username, char[] password) throws CredentialStoreException {

        String hashAlgo = getHashAlgo();
        int iterationCount = getIterationCount();
        int keyLength = getKeyLength();

        String salt = IdentityUserMgtUtil.generateUUID();

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
            //Store password.
            NamedPreparedStatement addPasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_CREDENTIAL));
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD, hashedPassword);
            addPasswordPreparedStatement.getPreparedStatement().executeUpdate();

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

        } catch (SQLException e) {
            throw new CredentialStoreException("Error while storing user credential.", e);
        }
    }

    private int getKeyLength() {
        int keyLength;
        Object keyLengthObj = credentialStoreConfig.getProperties().get(ConnectorConstants.KEY_LENGTH);
        if (keyLengthObj != null) {
            keyLength = (Integer) keyLengthObj;
        } else {
            keyLength = 256;
        }
        return keyLength;
    }

    private int getIterationCount() {
        int iterationCount;
        Object iterationCountObj = credentialStoreConfig.getProperties().get(ConnectorConstants.ITERATION_COUNT);
        if (iterationCountObj != null) {
            iterationCount = (Integer) iterationCountObj;
        } else {
            iterationCount = 4096;
        }
        return iterationCount;
    }

    private String getHashAlgo() {
        String hashAlgo;
        hashAlgo = credentialStoreConfig.getProperties().getProperty(ConnectorConstants.HASH_ALGO);
        if (hashAlgo == null) {
            hashAlgo = "SHA256";
        }
        return hashAlgo;
    }

    private void updateCredential(String username, char[] password) throws CredentialStoreException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            String hashAlgo = getHashAlgo();
            int iterationCount = getIterationCount();
            int keyLength = getKeyLength();

            String salt = IdentityUserMgtUtil.generateUUID();

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

            //Update password.
            NamedPreparedStatement updatePasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_CREDENTIAL));
            updatePasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            updatePasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD, hashedPassword);
            updatePasswordPreparedStatement.getPreparedStatement().executeUpdate();

            NamedPreparedStatement updatePasswordInfo = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_PASSWORD_INFO));
            updatePasswordInfo.setInt(ConnectorConstants.SQLPlaceholders.ITERATION_COUNT, iterationCount);
            updatePasswordInfo.setInt(ConnectorConstants.SQLPlaceholders.KEY_LENGTH, keyLength);
            updatePasswordInfo.setString(ConnectorConstants.SQLPlaceholders.HASH_ALGO, hashAlgo);
            updatePasswordInfo.setString(ConnectorConstants.SQLPlaceholders.PASSWORD_SALT, salt);
            updatePasswordInfo.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            updatePasswordInfo.getPreparedStatement().executeUpdate();

        } catch (SQLException e) {
            throw new CredentialStoreException("Error while updating the password.", e);
        }
    }

    private String hashPassword(char[] password, String hashAlgo, String salt, int iterationCount, int keyLength)
            throws SQLException, CredentialStoreException, NoSuchAlgorithmException {

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
