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
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * JDBC Identity store connector related tests.
 */
public class JDBCIdentityConnectorTests extends JDBCConnectorTests {


    @Test(priority = 24)
    public void testIsUserInGroupValid() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        assertTrue(identityStore.isUserInGroup(DEFAULT_USER_ID, DEFAULT_GROUP_ID));
    }

    @Test(priority = 25)
    public void testGetUserFromUsername() throws IdentityStoreException, UserNotFoundException {

        IdentityStore identityStore = realmService.getIdentityStore();
        User user  = identityStore.getUser(DEFAULT_USERNAME);
        assertNotNull(user);
    }

//    @Test(priority = 26)
//    public void testGetUserFromUserId() throws IdentityStoreException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        User user  = identityStore.getUserFromId(DEFAULT_USER_ID, defaultDomain);
//        assertNotNull(user);
//    }

    @Test(priority = 27)
    public void testListUsers() throws IdentityStoreException {

        String filterPattern = "*";

        IdentityStore identityStore = realmService.getIdentityStore();
        List<User> users = identityStore.listUsers(filterPattern, 0, -1);

        assertFalse(users.isEmpty());
    }

    @Test(priority = 28)
    public void testGetUserAttributeValues() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Attribute> claims = identityStore.getUserAttributeValues(DEFAULT_USER_ID);

        assertFalse(claims.isEmpty());
    }

    @Test(priority = 29)
    public void testGetUserAttributeValuesFromAttributeNames() throws IdentityStoreException {

        List<String> attributeNames = new ArrayList<>();
        attributeNames.add("firstName");
        attributeNames.add("lastName");

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Attribute> claims = identityStore.getUserAttributeValues(DEFAULT_USER_ID, attributeNames);

        assertFalse(claims.isEmpty());
    }

//    @Test(priority = 30)
//    public void testGetClaims() throws IdentityStoreException, ClaimManagerException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        User user  = identityStore.getUserFromId(DEFAULT_USER_ID, defaultDomain);
//        List<Claim> claims = user.getClaims();
//        assertTrue(claims != null && claims.size() > 0);
//    }

//    @Test(priority = 31)
//    public void testGetClaimsFromClaimURIs() throws IdentityStoreException, ClaimManagerException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        User user  = identityStore.getUserFromId(DEFAULT_USER_ID, defaultDomain);
//        List<String> claimURIs = Arrays.asList("http://wso2.org/claims/firstName", "http://wso2.org/claims/lastName");
//        List<Claim> claims = user.getClaims(claimURIs);
//        assertTrue(claims != null && claims.size() == 2);
//    }

    @Test(priority = 32)
    public void testGetGroup() throws IdentityStoreException, GroupNotFoundException {

        IdentityStore identityStore = realmService.getIdentityStore();
        Group group = identityStore.getGroup(DEFAULT_GROUP);

        assertNotNull(group);
    }

//    @Test(priority = 33)
//    public void testGetGroupFromId() throws IdentityStoreException {
//
//        IdentityStore identityStore = realmService.getIdentityStore();
//        Group group = identityStore.getGroupFromId(DEFAULT_GROUP_ID, defaultDomain);
//
//        assertNotNull(group);
//    }

    @Test(priority = 34)
    public void testListGroups() throws IdentityStoreException {

        String filterPattern = "*";

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Group> groups = identityStore.listGroups(filterPattern, 0, -1);

        assertFalse(groups.isEmpty());
    }

    @Test(priority = 35)
    public void testGetGroupsOfUser() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Group> groups = identityStore.getGroupsOfUser(DEFAULT_USER_ID);
        assertFalse(groups.isEmpty());
    }

    @Test(priority = 36)
    public void testGetUsersOfGroup() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<User> users = identityStore.getUsersOfGroup(DEFAULT_GROUP_ID);
        assertFalse(users.isEmpty());
    }
}
