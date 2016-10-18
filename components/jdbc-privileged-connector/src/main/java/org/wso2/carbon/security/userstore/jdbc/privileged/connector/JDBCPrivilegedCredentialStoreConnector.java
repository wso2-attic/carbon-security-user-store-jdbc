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
import org.wso2.carbon.security.caas.internal.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.userstore.jdbc.connector.JDBCCredentialStoreConnector;

import javax.security.auth.callback.Callback;
import javax.sql.DataSource;

/**
 * JDBC connector for the credential store.
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
}
