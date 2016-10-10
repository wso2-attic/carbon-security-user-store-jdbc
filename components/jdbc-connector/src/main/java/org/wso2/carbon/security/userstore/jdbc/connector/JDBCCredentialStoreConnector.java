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
import org.wso2.carbon.security.caas.api.CarbonCallback;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.constant.UserCoreConstants;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.util.PasswordHandler;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.security.userstore.jdbc.util.DatabaseUtil;
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
 * @since 1.0.0
 */
public class JDBCCredentialStoreConnector extends JDBCStoreConnector implements CredentialStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCCredentialStoreConnector.class);

    private String credentialStoreId;
    private CredentialStoreConnectorConfig credentialStoreConfig;
    private DataSource dataSource;

    public void init(String storeId, CredentialStoreConnectorConfig configuration) throws CredentialStoreException {

        Properties properties = configuration.getStoreProperties();
        this.credentialStoreConfig = configuration;
        this.credentialStoreId = storeId;

        try {
            this.dataSource = DatabaseUtil.getInstance().getDataSource(properties
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
    public String getCredentialStoreId() {
        return credentialStoreId;
    }

    @Override
    public void authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {

        Map<String, String> userData = null;
        char [] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            } else if (callback instanceof CarbonCallback) {
                userData = (Map<String, String>) ((CarbonCallback) callback).getContent();
            }
        }

        if (userData == null || password == null || userData.isEmpty()) {
            throw new AuthenticationFailure("Data required for authentication is missing.");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement getPasswordInfoPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_INFO));
            getPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_ID,
                    userData.get(UserCoreConstants.USER_ID));

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
            PasswordHandler passwordHandler = DatabaseUtil.getInstance().getPasswordHandler(credentialStoreConfig
                    .getStoreProperties().getProperty(UserCoreConstants.PASSWORD_HANDLER_NAME));

            if (passwordHandler == null) {
                passwordHandler = new DefaultPasswordHandler();
                if (log.isDebugEnabled()) {
                    log.debug("No password handler present. Using the default password handler.");
                }
            }

            passwordHandler.setIterationCount(iterationCount);
            passwordHandler.setKeyLength(keyLength);

            String hashedPassword = passwordHandler.hashPassword(password, salt, hashAlgo);

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
            if (callback instanceof  CarbonCallback) {
                carbonCallbackPresent = true;
            }
            if (callback instanceof  PasswordCallback) {
                passwordCallbackPresent = true;
            }
        }

        return carbonCallbackPresent && passwordCallbackPresent;
    }

    @Override
    public CredentialStoreConnectorConfig getCredentialStoreConfig() {
        return credentialStoreConfig;
    }
}
