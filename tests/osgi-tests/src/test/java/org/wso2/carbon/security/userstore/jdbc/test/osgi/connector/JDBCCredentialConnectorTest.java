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

package org.wso2.carbon.security.userstore.jdbc.test.osgi.connector;

import org.ops4j.pax.exam.util.Filter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.security.caas.api.CarbonCallback;
import org.wso2.carbon.security.caas.user.core.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.constant.UserCoreConstants;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

/**
 * JDBC Credential store connector tests.
 */
public class JDBCCredentialConnectorTest extends JDBCConnectorTests {

    @Inject
    @Filter("(connector-type=JDBCCredentialStore)")
    protected CredentialStoreConnectorFactory credentialStoreConnectorFactory;

    private CredentialStoreConnector credentialStoreConnector;


    private void initConnector() throws CredentialStoreException {
        Assert.assertNotNull(credentialStoreConnectorFactory);
        credentialStoreConnector = credentialStoreConnectorFactory.getInstance();

        CredentialStoreConnectorConfig credentialStoreConnectorConfig = new CredentialStoreConnectorConfig();
        credentialStoreConnectorConfig.setConnectorId("JDBCCS1");
        credentialStoreConnectorConfig.setConnectorType("JDBCCredentialStore");
        credentialStoreConnectorConfig.setDomainName("carbon");
        credentialStoreConnectorConfig.setPrimaryAttribute("username");

        Properties properties = new Properties();
        properties.setProperty("dataSource", "WSO2_CARBON_DB");
        properties.setProperty("hashAlgorithm", "SHA256");
        properties.setProperty("databaseType", "MySQL");
        credentialStoreConnectorConfig.setProperties(properties);
        credentialStoreConnector.init(credentialStoreConnectorConfig);
    }

    @Test
    public void testAuthentication() throws CredentialStoreException, IdentityStoreException, AuthenticationFailure {

        initConnector();
        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        CarbonCallback<Map> carbonCallback = new CarbonCallback<>(null);

        Map<String, String> userData = new HashMap<>();
        userData.put(UserCoreConstants.USER_ID, "admin");
        carbonCallback.setContent(userData);

        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;
        callbacks[1] = carbonCallback;

        credentialStoreConnector.authenticate(callbacks);

        Assert.assertTrue(true);
    }
}
