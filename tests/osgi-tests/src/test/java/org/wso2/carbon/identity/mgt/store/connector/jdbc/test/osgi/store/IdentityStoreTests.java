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

package org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.store;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.mgt.bean.User;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.model.UserModel;
import org.wso2.carbon.identity.mgt.store.IdentityStore;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.JDBCConnectorTests;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.TestConstants;

import java.util.ArrayList;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

/**
 * JDBC Identity store connector related tests.
 */
public class IdentityStoreTests extends JDBCConnectorTests {

    @Test(priority = 1)
    public void testAddUser() throws IdentityStoreException, UserNotFoundException, AuthenticationFailure {

        IdentityStore identityStore = realmService.getIdentityStore();
        UserModel userModel = new UserModel();
        List<Claim> claimList = new ArrayList<>();
        Claim claim1 = new Claim(TestConstants.LOCAL_CLAIM_DIALECT, TestConstants.CLAIM_USERNAME, "johndoe");
        claimList.add(claim1);
        Claim claim2 = new Claim(TestConstants.LOCAL_CLAIM_DIALECT, TestConstants.CLAIM_FIRST_NAME, "John");
        claimList.add(claim2);
        Claim claim3 = new Claim(TestConstants.LOCAL_CLAIM_DIALECT, TestConstants.CLAIM_LAST_NAME, "Doe");
        claimList.add(claim3);
        userModel.setClaims(claimList);

        List<Callback> callbackList = new ArrayList<>();
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});
        callbackList.add(passwordCallback);
        userModel.setCredentials(callbackList);

        User addUser = identityStore.addUser(userModel);
        User getUser = identityStore.getUser(claim1);
        Assert.assertNotNull(addUser);
        Assert.assertNotNull(getUser);
        Assert.assertEquals(getUser.getUniqueUserId(), addUser.getUniqueUserId());
    }

    @Test(priority = 2)
    public void testAuthenticate() throws IdentityStoreException, UserNotFoundException, AuthenticationFailure {

        IdentityStore identityStore = realmService.getIdentityStore();

        Callback[] callbacks = new Callback[1];

        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});
        callbacks[0] = passwordCallback;


        Claim claim = new Claim(TestConstants.LOCAL_CLAIM_DIALECT, TestConstants.CLAIM_USERNAME, "johndoe");

        identityStore.authenticate(claim, callbacks, "PRIMARY");
    }

}
