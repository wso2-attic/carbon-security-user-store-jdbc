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

package org.wso2.carbon.security.connector.osgi;

import org.testng.annotations.Test;
import org.wso2.carbon.security.caas.user.core.context.AuthenticationContext;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.store.CredentialStore;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import static org.testng.Assert.assertNotNull;

/**
 * JDBC Credential store connector tests.
 */
public class JDBCCredentialConnectorTest extends JDBCConnectorTests {

    public JDBCCredentialConnectorTest() throws Exception {
        super();
    }

    @Test
    public void testAuthentication() throws CredentialStoreException, IdentityStoreException, AuthenticationFailure {

        Callback[] callbacks = new Callback[2];
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        NameCallback nameCallback = new NameCallback("username");

        nameCallback.setName("admin");
        passwordCallback.setPassword(new char[] {'a', 'd', 'm', 'i', 'n'});

        callbacks[0] = passwordCallback;
        callbacks[1] = nameCallback;

        CredentialStore authManager = realmService.getCredentialStore();

        AuthenticationContext authenticationContext = authManager.authenticate(callbacks);
        assertNotNull(authenticationContext);
    }
}
