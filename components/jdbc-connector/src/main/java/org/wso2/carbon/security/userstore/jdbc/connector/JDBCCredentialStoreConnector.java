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
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.util.UserCoreUtil;
import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.constant.DatabaseColumnNames;
import org.wso2.carbon.security.userstore.jdbc.util.DatabaseUtil;
import org.wso2.carbon.security.userstore.jdbc.util.NamedPreparedStatement;
import org.wso2.carbon.security.userstore.jdbc.util.UnitOfWork;

import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.sql.DataSource;

/**
 * JDBC connector for the credential store.
 * @since 1.0.0
 */
public class JDBCCredentialStoreConnector extends JDBCStoreConnector implements CredentialStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCCredentialStoreConnector.class);

    private String credentialStoreId;
    private CredentialStoreConfig credentialStoreConfig;
    private DataSource dataSource;

    public void init(String storeId, CredentialStoreConfig configuration) throws CredentialStoreException {

        Properties properties = configuration.getStoreProperties();
        this.credentialStoreConfig = configuration;
        this.credentialStoreId = storeId;

        try {
            this.dataSource = DatabaseUtil.getInstance().getDataSource(properties
                    .getProperty(ConnectorConstants.DATA_SOURCE));
        } catch (DataSourceException e) {
            throw new CredentialStoreException("Error while setting the data source.", e);
        }

        loadQueries((String) properties.get(ConnectorConstants.DATABASE_TYPE));

        if (log.isDebugEnabled()) {
            log.debug(String.format("JDBC credential store with id %s initialized successfully.", credentialStoreId));
        }
    }

    @Override
    public String getCredentialStoreId() {
        return credentialStoreId;
    }

    @Override
    public User.UserBuilder authenticate(Callback[] callbacks) throws CredentialStoreException, AuthenticationFailure {

        String username = null;
        char [] password = null;

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getName();
            } else if (callback instanceof PasswordCallback) {
                password = ((PasswordCallback) callback).getPassword();
            }
        }

        if (username == null || password == null) {
            throw new AuthenticationFailure("Username or password is null");
        }

        try (UnitOfWork unitOfWork = UnitOfWork.beginTransaction(dataSource.getConnection())) {

            NamedPreparedStatement getPasswordInfoPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_INFO));
            getPasswordInfoPreparedStatement.setString("username", username);

            String hashAlgo;
            String salt;

            try (ResultSet resultSet = getPasswordInfoPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new CredentialStoreException("Unable to retrieve password information.");
                }

                hashAlgo = resultSet.getString(DatabaseColumnNames.PasswordInfo.HASH_ALGO);
                salt = resultSet.getString(DatabaseColumnNames.PasswordInfo.PASSWORD_SALT);
            }

            NamedPreparedStatement comparePasswordPreparedStatement = new NamedPreparedStatement(
                    unitOfWork.getConnection(),
                    sqlQueries.get(ConnectorConstants.QueryTypes.SQL_QUERY_COMPARE_PASSWORD_HASH));

            String hashedPassword = UserCoreUtil.hashPassword(password, salt, hashAlgo);
            comparePasswordPreparedStatement.setString("hashed_password", hashedPassword);
            comparePasswordPreparedStatement.setString("username", username);

            try (ResultSet resultSet = comparePasswordPreparedStatement.getPreparedStatement().executeQuery()) {

                if (!resultSet.next()) {
                    throw new AuthenticationFailure("Invalid username or password");
                }

                String userUniqueId = resultSet.getString(DatabaseColumnNames.User.USER_UNIQUE_ID);
                String tenantDomain = resultSet.getString(DatabaseColumnNames.Tenant.DOMAIN_NAME);
                String identityStoreId = resultSet.getString(DatabaseColumnNames.User.IDENTITY_STORE_ID);

                return new User.UserBuilder().setUserName(username).setUserId(userUniqueId)
                        .setIdentityStoreId(identityStoreId).setCredentialStoreId(credentialStoreId)
                        .setTenantDomain(tenantDomain);
            }
        } catch (SQLException | NoSuchAlgorithmException e) {
            throw new CredentialStoreException("Exception occurred while authenticating the user", e);
        }
    }

    @Override
    public boolean canHandle(Callback[] callbacks) {

        boolean nameCallbackPresent = false;
        boolean passwordCallbackPresent = false;

        for (Callback callback : callbacks) {
            if (callback instanceof  NameCallback) {
                nameCallbackPresent = true;
            }
            if (callback instanceof  PasswordCallback) {
                passwordCallbackPresent = true;
            }
        }

        return nameCallbackPresent && passwordCallbackPresent;
    }

    @Override
    public CredentialStoreConfig getCredentialStoreConfig() {
        return credentialStoreConfig;
    }
}
