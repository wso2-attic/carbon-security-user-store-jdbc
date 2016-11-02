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
import org.wso2.carbon.identity.user.mgt.store.connector.PrivilegedCredentialStoreConnector;
import org.wso2.carbon.security.caas.api.CarbonCallback;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.constant.UserCoreConstants;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.util.PasswordHandler;
import org.wso2.carbon.security.userstore.jdbc.connector.JDBCCredentialStoreConnector;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.privileged.constant.PrivilegedConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.util.DatabaseUtil;
import org.wso2.carbon.security.userstore.jdbc.util.DefaultPasswordHandler;
import org.wso2.carbon.security.userstore.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.security.userstore.jdbc.util.UnitOfWork;

import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.sql.DataSource;

/**
 * JDBC connector for the credential store.
 *
 * @since 1.0.0
 */
public class JDBCPrivilegedCredentialStoreConnector extends JDBCCredentialStoreConnector implements
        PrivilegedCredentialStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCPrivilegedCredentialStoreConnector.class);

    private String credentialStoreId;
    private CredentialStoreConnectorConfig credentialStoreConfig;
    private DataSource dataSource;


    @Override
    public void updateCredential(Callback[] callbacks) throws CredentialStoreException {

    }

    @Override
    public void updateCredential(String s, Callback[] callbacks) throws CredentialStoreException {

    }

    public void addCredential(Callback[] callbacks) throws CredentialStoreException {
        Map<String, String> userData = null;
        char[] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof CarbonCallback) {
                userData = (Map<String, String>) ((CarbonCallback) callback).getContent();
            }
        }

        if (userData == null || userData.isEmpty()) {
            throw new CredentialStoreException("Data required for authentication is missing.");
        }

        addCredential(userData.get(UserCoreConstants.USER_ID), callbacks);
    }

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

        //TODO need these in a config file
        String hashAlgo = "SHA25";
        int iterationCount = 4096;
        int keyLength = 256;

        //TODO is there another way to generate the salt
        String salt = UUID.randomUUID().toString();

        // Get a password handler if there is a one. Otherwise use the default one.
        PasswordHandler passwordHandler = DatabaseUtil.getInstance().getPasswordHandler(credentialStoreConfig
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
                    sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_PASSWORD_INFO));
            addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD_SALT, salt);
            addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.HASH_ALGO, hashAlgo);
            addPasswordInfoPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.ITERATION_COUNT, iterationCount);
            addPasswordInfoPreparedStatement.setInt(ConnectorConstants.SQLPlaceholders.KEY_LENGTH, keyLength);
            addPasswordInfoPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            addPasswordInfoPreparedStatement.getPreparedStatement().executeUpdate();

            //Store password.
            NamedPreparedStatement addPasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_PASSWORD));
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.USER_UNIQUE_ID, username);
            addPasswordPreparedStatement.setString(ConnectorConstants.SQLPlaceholders.PASSWORD, hashedPassword);
            addPasswordPreparedStatement.getPreparedStatement().executeUpdate();
        } catch (SQLException e) {
            throw new CredentialStoreException("Error while storing user credential.", e);
        }
    }
}
