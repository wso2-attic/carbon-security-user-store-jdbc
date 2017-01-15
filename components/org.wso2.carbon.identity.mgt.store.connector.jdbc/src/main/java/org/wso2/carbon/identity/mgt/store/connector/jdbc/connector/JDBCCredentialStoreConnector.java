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
import org.wso2.carbon.identity.mgt.connector.CredentialStoreConnector;
import org.wso2.carbon.identity.mgt.connector.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;
import org.wso2.carbon.identity.mgt.impl.util.IdentityUserMgtUtil;
import org.wso2.carbon.identity.mgt.impl.util.PasswordHandler;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.internal.ConnectorDataHolder;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.util.DefaultPasswordHandler;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.util.UnitOfWork;
import org.wso2.carbon.security.caas.user.core.constant.UserCoreConstants;

import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.sql.DataSource;

/**
 * Connector for the JDBC based credential store.
 *
 * @since 1.0.0
 */
public class JDBCCredentialStoreConnector extends JDBCStoreConnector implements CredentialStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCCredentialStoreConnector.class);

    private String credentialStoreId;
    private CredentialStoreConnectorConfig credentialStoreConfig;
    private DataSource dataSource;

    @Override
    public void init(CredentialStoreConnectorConfig configuration) throws CredentialStoreConnectorException {

        Map<String, String> properties = configuration.getProperties();
        this.credentialStoreConfig = configuration;
        this.credentialStoreId = configuration.getConnectorId();

        try {
            this.dataSource = ConnectorDataHolder.getInstance().getDataSource(properties
                    .get(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new CredentialStoreConnectorException("Error while setting the data source.", e);
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
    public void authenticate(String connectorUserId, Callback[] callbacks) throws CredentialStoreConnectorException,
            AuthenticationFailure {

        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if (password == null) {
            throw new AuthenticationFailure("Data required for authentication is missing.");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement comparePasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_DATA));

            comparePasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID, connectorUserId);

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
            throw new CredentialStoreConnectorException("Exception occurred while authenticating the user", e);
        }
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean canStore(Callback[] callbacks) {

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                return true;
            }
        }

        return false;
    }

    @Override
    public CredentialStoreConnectorConfig getCredentialStoreConfig() {
        return credentialStoreConfig;
    }

    @Override
    public String updateCredentials(String username, List<Callback> callbacks) throws
            CredentialStoreConnectorException {
        char[] password = null;
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        updateCredential(username, password);
        return username;
    }

    @Override
    public String addCredential(List<Callback> callbacks) throws CredentialStoreConnectorException {

        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                if (password == null) {
                    password = ((PasswordCallback) callback).getPassword();
                } else {
                    throw new CredentialStoreConnectorException("Multiple passwords found");
                }
            }
        }

        String userId = IdentityUserMgtUtil.generateUUID();
        Map<String, char[]> passwordMap = new HashMap<>();
        passwordMap.put(userId, password);

        addCredential(passwordMap);

        return userId;

    }

    @Override
    public Map<String, String> addCredentials(Map<String, List<Callback>> userUniqueIdToCallbacksMap) throws
            CredentialStoreConnectorException {

        Map<String, char[]> passwordMap = new HashMap<>();
        Map<String, String> usersIds = new HashMap<>();
        for (Map.Entry<String, List<Callback>> entry : userUniqueIdToCallbacksMap.entrySet()) {
            char[] password = null;

            for (Callback callback : entry.getValue()) {
                if (callback instanceof PasswordCallback) {
                    if (password == null) {
                        password = ((PasswordCallback) callback).getPassword();
                    } else {
                        throw new CredentialStoreConnectorException("Multiple passwords found");
                    }
                }
            }

            String userId = IdentityUserMgtUtil.generateUUID();
            passwordMap.put(userId, password);
            usersIds.put(entry.getKey(), userId);

        }
        addCredential(passwordMap);
        return usersIds;
    }

    @Override
    public String updateCredentials(String userIdentifier, List<Callback> credentialsToAdd,
                                    List<Callback> credentialsToRemove) throws CredentialStoreConnectorException {

        char[] password = null;
        for (Callback callback : credentialsToAdd) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }
        // As the credential store store containing the passwords can have one password per user, if there is a
        // password in the credentialsToAdd list, update the credential of the user. Otherwise if there is a
        // password in the credentialsToRemove, delete it
        if (password != null) {
            updateCredential(userIdentifier, password);
        } else {
            for (Callback callback : credentialsToRemove) {
                if (callback instanceof PasswordCallback) {
                    password = ((PasswordCallback) callback).getPassword();
                }
            }
            //TODO: do we need to check if this password is matching with the password stored?
            if (password != null) {
                deleteCredential(userIdentifier);
            }
        }
        return userIdentifier;
    }

    @Override
    public void deleteCredential(String username) throws CredentialStoreConnectorException {

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {

            NamedPreparedStatement deleteCredentialPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_CREDENTIAL));

            deleteCredentialPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID,
                    username);

            deleteCredentialPreparedStatement.getPreparedStatement().executeUpdate();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new CredentialStoreConnectorException("Exception occurred while deleting the credential", e);
        }
    }

    private void addCredential(Map<String, char[]> passwordMap) throws CredentialStoreConnectorException {

        String hashAlgo = getHashAlgo();
        int iterationCount = getIterationCount();
        int keyLength = getKeyLength();

        String salt = IdentityUserMgtUtil.generateUUID();

        // Get a password handler if there is a one. Otherwise use the default one.
        PasswordHandler passwordHandler = ConnectorDataHolder.getInstance().getPasswordHandler(credentialStoreConfig
                .getProperties().get(UserCoreConstants.PASSWORD_HANDLER_NAME));

        if (passwordHandler == null) {
            passwordHandler = new DefaultPasswordHandler();
            if (log.isDebugEnabled()) {
                log.debug("No password handler present. Using the default password handler.");
            }
        }

        passwordHandler.setIterationCount(iterationCount);
        passwordHandler.setKeyLength(keyLength);

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
            NamedPreparedStatement addPasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_CREDENTIAL));
            NamedPreparedStatement addPasswordInfoPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PASSWORD_INFO));
            for (Map.Entry<String, char[]> entry : passwordMap.entrySet()) {
                String hashedPassword;
                try {
                    hashedPassword = passwordHandler.hashPassword(entry.getValue(), salt, hashAlgo);
                } catch (NoSuchAlgorithmException e) {
                    throw new CredentialStoreConnectorException("Error while hashing the password.", e);
                }

                //Store password.

                addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, entry
                        .getKey());

                addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD, hashedPassword);
                addPasswordPreparedStatement.getPreparedStatement().addBatch();

                //Store password info.
                addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD_SALT, salt);
                addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.HASH_ALGO, hashAlgo);
                addPasswordInfoPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.ITERATION_COUNT,
                        iterationCount);
                addPasswordInfoPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.KEY_LENGTH, keyLength);
                addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, entry
                        .getKey());
                addPasswordInfoPreparedStatement.getPreparedStatement().addBatch();
            }
            addPasswordPreparedStatement.getPreparedStatement().executeBatch();
            addPasswordInfoPreparedStatement.getPreparedStatement().executeBatch();
            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new CredentialStoreConnectorException("Error while storing user credential.", e);
        }

    }

    private int getKeyLength() {
        int keyLength;
        String keyLengthObj = credentialStoreConfig.getProperties().get(ConnectorConstants.KEY_LENGTH);
        if (keyLengthObj != null) {
            keyLength = Integer.parseInt(keyLengthObj);
        } else {
            keyLength = 256;
        }
        return keyLength;
    }

    private int getIterationCount() {
        int iterationCount;
        String iterationCountObj = credentialStoreConfig.getProperties().get(ConnectorConstants.ITERATION_COUNT);
        if (iterationCountObj != null) {
            iterationCount = Integer.parseInt(iterationCountObj);
        } else {
            iterationCount = 4096;
        }
        return iterationCount;
    }

    private String getHashAlgo() {
        String hashAlgo;
        hashAlgo = credentialStoreConfig.getProperties().get(ConnectorConstants.HASH_ALGO);
        if (hashAlgo == null) {
            hashAlgo = "SHA256";
        }
        return hashAlgo;
    }

    private void updateCredential(String username, char[] password) throws CredentialStoreConnectorException {

        String hashAlgo = getHashAlgo();
        int iterationCount = getIterationCount();
        int keyLength = getKeyLength();

        String salt = IdentityUserMgtUtil.generateUUID();

        // Get a password handler if there is a one. Otherwise use the default one.
        PasswordHandler passwordHandler = ConnectorDataHolder.getInstance().getPasswordHandler(credentialStoreConfig
                .getProperties().get(UserCoreConstants.PASSWORD_HANDLER_NAME));

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
            throw new CredentialStoreConnectorException("Error while hashing the password.", e);
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection(), false)) {
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

            unitOfWork.endTransaction();
        } catch (SQLException e) {
            throw new CredentialStoreConnectorException("Error while updating the password.", e);
        }
    }

    private String hashPassword(char[] password, String hashAlgo, String salt, int iterationCount, int keyLength)
            throws SQLException, CredentialStoreConnectorException, NoSuchAlgorithmException {

        // Get a password handler if there is a one. Otherwise use the default one.
        PasswordHandler passwordHandler = ConnectorDataHolder.getInstance().getPasswordHandler(credentialStoreConfig
                .getProperties().get(UserCoreConstants.PASSWORD_HANDLER_NAME));

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
