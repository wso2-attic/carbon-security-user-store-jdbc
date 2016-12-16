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

package org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.connector;

import org.ops4j.pax.exam.util.Filter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.mgt.connector.CredentialStoreConnector;
import org.wso2.carbon.identity.mgt.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.identity.mgt.connector.config.CredentialStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.CredentialStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.JDBCConnectorTests;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
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

    private static CredentialStoreConnector credentialStoreConnector;
    private static String connectorUserId;

    private void initConnector() throws CredentialStoreConnectorException {
        Assert.assertNotNull(credentialStoreConnectorFactory);
        credentialStoreConnector = credentialStoreConnectorFactory.getInstance();

        CredentialStoreConnectorConfig credentialStoreConnectorConfig = new CredentialStoreConnectorConfig();
        credentialStoreConnectorConfig.setConnectorId("JDBCCS1");
        credentialStoreConnectorConfig.setConnectorType("JDBCCredentialStore");

        Map<String, String> properties = new HashMap<>();
        properties.put("dataSource", "WSO2_CARBON_DB");
        properties.put("hashAlgorithm", "SHA256");
        properties.put("databaseType", "MySQL");
        credentialStoreConnectorConfig.setProperties(properties);
        credentialStoreConnector.init(credentialStoreConnectorConfig);
    }

    @Test(priority = 1)
    public void testAuthentication() throws CredentialStoreConnectorException, IdentityStoreException,
            AuthenticationFailure {

        //As beforeClass is not supported, connector is initialized here
        initConnector();
        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;

        credentialStoreConnector.authenticate("admin", callbacks);
        //No need for assertions. If the authentication fails, the test will fail
    }

    //TODO need to change expectedException to AuthenticationFailure
    @Test(priority = 2, expectedExceptions = {Throwable.class}, expectedExceptionsMessageRegExp =
            "Invalid username or password")
    public void testAuthenticationFailure() throws CredentialStoreConnectorException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[1];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'm'});

        callbacks[0] = passwordCallback;

        credentialStoreConnector.authenticate("admin", callbacks);
    }

    //TODO need to change the expectedExceptions to CredentialStoreException
    @Test(priority = 3, expectedExceptions = {Throwable.class}, expectedExceptionsMessageRegExp =
            "Invalid username or password*")
    public void testAuthenticationIncorrectUser() throws CredentialStoreConnectorException, IdentityStoreException,
            AuthenticationFailure {

        Callback[] callbacks = new Callback[1];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;

        credentialStoreConnector.authenticate("admin1", callbacks);
    }

    @Test(priority = 4)
    public void testAddCredentialCallback() throws CredentialStoreConnectorException, IdentityStoreException,
            AuthenticationFailure {

        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'m', 'a', 'd', 'u', 'r', 'a', 'n', 'g', 'a'});

        connectorUserId = credentialStoreConnector.addCredential(Collections.singletonList(passwordCallback));

        credentialStoreConnector.authenticate(connectorUserId, new Callback[]{passwordCallback});
        //No need for assertions. If the authentication fails, the test will fail
    }

    @Test(priority = 5)
    public void testUpdateCredentialCallback() throws CredentialStoreConnectorException, IdentityStoreException,
            AuthenticationFailure {

        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'m', 'a', 'd', 'u', 'r', 'a', 'n', 'g', 'a', '1'});

        credentialStoreConnector.updateCredentials(connectorUserId, Collections.singletonList(passwordCallback));
        credentialStoreConnector.authenticate(connectorUserId, new Callback[]{passwordCallback});
        //No need for assertions. If the authentication fails, the test will fail
    }

    @Test(priority = 6, expectedExceptions = {Throwable.class}, expectedExceptionsMessageRegExp =
            "Invalid username or password*")
    public void testDeleteCredential() throws CredentialStoreConnectorException, AuthenticationFailure {

        credentialStoreConnector.deleteCredential(connectorUserId);

        Callback[] callbacks = new Callback[1];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);

        passwordCallback.setPassword(new char[]{'m', 'a', 'd', 'u', 'r', 'a', 'n', 'g', 'a'});

        callbacks[0] = passwordCallback;

        credentialStoreConnector.authenticate(connectorUserId, callbacks);
    }
}
