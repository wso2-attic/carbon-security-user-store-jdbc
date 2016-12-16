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
import org.wso2.carbon.identity.mgt.Group;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.User;
import org.wso2.carbon.identity.mgt.bean.GroupBean;
import org.wso2.carbon.identity.mgt.bean.UserBean;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.JDBCConnectorTests;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.TestConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

/**
 * JDBC Identity store connector related tests.
 */
public class IdentityStoreTests extends JDBCConnectorTests {

    private static List<User> users = new ArrayList<>();
    private static List<Group> groups = new ArrayList<>();

    @Test(groups = "addUsers")
    public void testAddUser() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        UserBean userBean = new UserBean();
        List<Claim> claims = Arrays
                .asList(new Claim("http://wso2.org/claims", "http://wso2.org/claims/username", "lucifer"),
                        new Claim("http://wso2.org/claims", "http://wso2.org/claims/firstName", "Lucifer"),
                        new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Morningstar"),
                        new Claim("http://wso2.org/claims", "http://wso2.org/claims/email", "lucifer@wso2.com"));
        userBean.setClaims(claims);

        List<Callback> callbackList = new ArrayList<>();
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});
        callbackList.add(passwordCallback);
        userBean.setCredentials(callbackList);
        User user = realmService.getIdentityStore().addUser(userBean);

        Assert.assertNotNull(user, "Failed to receive the user.");
        Assert.assertNotNull(user.getUniqueUserId(), "Invalid user unique id.");

        users.add(user);
    }

    @Test(groups = "addUsers")
    public void testAddUserByDomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        UserBean userBean = new UserBean();
        List<Claim> claims = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/username", "chloe"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/firstName", "Chloe"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Decker"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/email", "chloe@wso2.com"));
        userBean.setClaims(claims);
        User user = realmService.getIdentityStore().addUser(userBean, "PRIMARY");

        Assert.assertNotNull(user, "Failed to receive the user.");
        Assert.assertNotNull(user.getUniqueUserId(), "Invalid user unique id.");

        users.add(user);
    }

    @Test(groups = "addUsers")
    public void testAddUsers() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        UserBean userBean1 = new UserBean();
        List<Claim> claims1 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/username", "dan"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/firstName", "Dan"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Espinoza"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/email", "dan@wso2.com"));
        userBean1.setClaims(claims1);

        UserBean userBean2 = new UserBean();
        List<Claim> claims2 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/username", "linda"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/firstName", "Linda"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Martin"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/email", "linda@wso2.com"));
        userBean2.setClaims(claims2);

        List<User> addedUsers = realmService.getIdentityStore().addUsers(Arrays.asList(userBean1, userBean2));

        Assert.assertNotNull(addedUsers, "Failed to receive the users.");
        Assert.assertTrue(!addedUsers.isEmpty() && addedUsers.size() == 2, "Number of users received in the response " +
                "is invalid.");

        users.addAll(addedUsers);
    }

    @Test(groups = "addUsers")
    public void testAddUsersByDomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        UserBean userBean1 = new UserBean();
        List<Claim> claims1 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/username", "ella"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/firstName", "Ella"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Lopez"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/email", "ella@wso2.com"));
        userBean1.setClaims(claims1);

        UserBean userBean2 = new UserBean();
        List<Claim> claims2 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/username", "trixie"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/firstName", "Trixie"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Decker"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/email", "trixie@wso2.com"));
        userBean2.setClaims(claims2);

        List<User> addedUsers = realmService.getIdentityStore().addUsers(Arrays.asList(userBean1, userBean2),
                "PRIMARY");

        Assert.assertNotNull(addedUsers, "Failed to receive the users.");
        Assert.assertTrue(!addedUsers.isEmpty() && addedUsers.size() == 2, "Number of users received in the response " +
                "is invalid.");

        users.addAll(addedUsers);
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testGetUserByUniqueUserId() throws IdentityStoreException, UserNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        User user = realmService.getIdentityStore().getUser(users.get(0).getUniqueUserId());

        Assert.assertNotNull(user, "Failed to receive the user.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testGetUserByClaim() throws IdentityStoreException, UserNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        User user = realmService.getIdentityStore()
                .getUser(new Claim("http://wso2.org/claims", "http://wso2" + ".org/claims/username", "lucifer"));

        Assert.assertNotNull(user, "Failed to receive the user.");

        Assert.assertNotNull(user.getUniqueUserId(), "Invalid user unique id.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testGetUserByClaimAndDomain() throws IdentityStoreException, UserNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        User user = realmService.getIdentityStore().getUser(new Claim("http://wso2.org/claims", "http://wso2" +
                ".org/claims/username", "chloe"), "PRIMARY");

        Assert.assertNotNull(user, "Failed to receive the user.");

        Assert.assertNotNull(user.getUniqueUserId(), "Invalid user unique id.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testListUsersByOffsetAndLength() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<User> users = realmService.getIdentityStore().listUsers(2, 3);

        Assert.assertNotNull(users, "Failed to list the users.");
        Assert.assertTrue(!users.isEmpty() && users.size() == 3, "Number of users received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testListUsersByOffsetAndLengthInADomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<User> users = realmService.getIdentityStore().listUsers(2, 3, "PRIMARY");

        Assert.assertNotNull(users, "Failed to list the users.");
        Assert.assertTrue(!users.isEmpty() && users.size() == 3, "Number of users received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testListUsersByClaimOffsetAndLength() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        Claim claim = new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Decker");
        List<User> users = realmService.getIdentityStore().listUsers(claim, 1, 2);

        Assert.assertNotNull(users, "Failed to list the users.");
        Assert.assertTrue(!users.isEmpty() && users.size() == 2, "Number of users received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testListUsersByClaimOffsetAndLengthInADomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        Claim claim = new Claim("http://wso2.org/claims", "http://wso2.org/claims/lastName", "Decker");
        List<User> users = realmService.getIdentityStore().listUsers(claim, 1, 2, "PRIMARY");

        Assert.assertNotNull(users, "Failed to list the users.");
        Assert.assertTrue(!users.isEmpty() && users.size() == 2, "Number of users received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testListUsersByMetaClaimFilterPatternOffsetAndLength() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        MetaClaim metaClaim = new MetaClaim("http://wso2.org/claims", "http://wso2.org/claims/lastName");
        List<User> users = realmService.getIdentityStore().listUsers(metaClaim, "*cke*", 1, 2);

        Assert.assertNotNull(users, "Failed to list the users.");
        Assert.assertTrue(!users.isEmpty() && users.size() == 2, "Number of users received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testListUsersByMetaClaimFilterPatternOffsetAndLengthInDomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        MetaClaim metaClaim = new MetaClaim("http://wso2.org/claims", "http://wso2.org/claims/lastName");
        List<User> users = realmService.getIdentityStore().listUsers(metaClaim, "*cke*", 1, 2, "PRIMARY");

        Assert.assertNotNull(users, "Failed to list the users.");
        Assert.assertTrue(!users.isEmpty() && users.size() == 2, "Number of users received in the response " +
                "is invalid.");
    }

    @Test(groups = "addGroups")
    public void testAddGroup() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        GroupBean groupBean = new GroupBean();
        List<Claim> claims = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/groupName", "Angels"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "Heaven"));
        groupBean.setClaims(claims);
        Group group = realmService.getIdentityStore().addGroup(groupBean);

        Assert.assertNotNull(group, "Failed to receive the group.");
        Assert.assertNotNull(group.getUniqueGroupId(), "Invalid group unique id.");

        groups.add(group);
    }

    @Test(groups = "addGroups")
    public void testAddGroupByDomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        GroupBean groupBean = new GroupBean();
        List<Claim> claims = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/groupName", "Demons"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "Hell"));
        groupBean.setClaims(claims);
        Group group = realmService.getIdentityStore().addGroup(groupBean, "PRIMARY");

        Assert.assertNotNull(group, "Failed to receive the group.");
        Assert.assertNotNull(group.getUniqueGroupId(), "Invalid group unique id.");

        groups.add(group);
    }

    @Test(groups = "addGroups")
    public void testAddGroups() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        GroupBean groupBean1 = new GroupBean();
        List<Claim> claims1 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/groupName", "humans"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "Society"));
        groupBean1.setClaims(claims1);

        GroupBean groupBean2 = new GroupBean();
        List<Claim> claims2 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/groupName", "children"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "Society"));
        groupBean2.setClaims(claims2);

        List<Group> addedGroups = realmService.getIdentityStore().addGroups(Arrays.asList(groupBean1, groupBean2));

        Assert.assertNotNull(addedGroups, "Failed to receive the groups.");
        Assert.assertTrue(!addedGroups.isEmpty() && addedGroups.size() == 2, "Number of groups received in the " +
                "response is invalid.");

        groups.addAll(addedGroups);
    }

    @Test(groups = "addGroups")
    public void testAddGroupsByDomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        GroupBean groupBean1 = new GroupBean();
        List<Claim> claims1 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/groupName", "SuperAngels"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "SuperHeaven"));
        groupBean1.setClaims(claims1);

        GroupBean groupBean2 = new GroupBean();
        List<Claim> claims2 = Arrays.asList(
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/groupName", "SuperDemons"),
                new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "SupperHell"));
        groupBean2.setClaims(claims2);

        List<Group> addedGroups = realmService.getIdentityStore().addGroups(Arrays.asList(groupBean1, groupBean2),
                "PRIMARY");

        Assert.assertNotNull(addedGroups, "Failed to receive the groups.");
        Assert.assertTrue(!addedGroups.isEmpty() && addedGroups.size() == 2, "Number of groups received in the " +
                "response is invalid.");

        groups.addAll(addedGroups);
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testGetGroupByUniqueGroupId() throws IdentityStoreException, GroupNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        Group group = realmService.getIdentityStore().getGroup(groups.get(0).getUniqueGroupId());

        Assert.assertNotNull(group, "Failed to receive the group.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testGetGroupByClaim() throws IdentityStoreException, GroupNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        Group group = realmService.getIdentityStore().getGroup(new Claim("http://wso2.org/claims", "http://wso2" +
                ".org/claims/groupName", "Angels"));

        Assert.assertNotNull(group, "Failed to receive the group.");

        Assert.assertNotNull(group.getUniqueGroupId(), "Invalid group unique id.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testGetGroupByClaimAndDomain() throws IdentityStoreException, GroupNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        Group group = realmService.getIdentityStore().getGroup(new Claim("http://wso2.org/claims", "http://wso2" +
                ".org/claims/groupName", "Demons"), "PRIMARY");

        Assert.assertNotNull(group, "Failed to receive the group.");

        Assert.assertNotNull(group.getUniqueGroupId(), "Invalid group unique id.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testListGroupsByOffsetAndLength() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<Group> groups = realmService.getIdentityStore().listGroups(2, 3);

        Assert.assertNotNull(groups, "Failed to list the users.");
        Assert.assertTrue(!groups.isEmpty() && groups.size() == 3, "Number of users received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testListGroupsByOffsetAndLengthInADomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<Group> groups = realmService.getIdentityStore().listGroups(2, 3, "PRIMARY");

        Assert.assertNotNull(groups, "Failed to list the groups.");
        Assert.assertTrue(!groups.isEmpty() && groups.size() == 3, "Number of groups received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testListGroupsByClaimOffsetAndLength() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        Claim claim = new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "Society");
        List<Group> groups = realmService.getIdentityStore().listGroups(claim, 1, 2);

        Assert.assertNotNull(groups, "Failed to list the groups.");
        Assert.assertTrue(!groups.isEmpty() && groups.size() == 2, "Number of groups received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testListGroupsByClaimOffsetAndLengthInADomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        Claim claim = new Claim("http://wso2.org/claims", "http://wso2.org/claims/organization", "Society");
        List<Group> groups = realmService.getIdentityStore().listGroups(claim, 1, 2, "PRIMARY");

        Assert.assertNotNull(groups, "Failed to list the groups.");
        Assert.assertTrue(!groups.isEmpty() && groups.size() == 2, "Number of groups received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testListGroupsByMetaClaimFilterPatternOffsetAndLength() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        MetaClaim metaClaim = new MetaClaim("http://wso2.org/claims", "http://wso2.org/claims/organization");
        List<Group> groups = realmService.getIdentityStore().listGroups(metaClaim, "*cie*", 1, 2);

        Assert.assertNotNull(groups, "Failed to list the groups.");
        Assert.assertTrue(!groups.isEmpty() && groups.size() == 2, "Number of groups received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addGroups"})
    public void testListGroupsByMetaClaimFilterPatternOffsetAndLengthInDomain() throws IdentityStoreException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        MetaClaim metaClaim = new MetaClaim("http://wso2.org/claims", "http://wso2.org/claims/organization");
        List<Group> groups = realmService.getIdentityStore().listGroups(metaClaim, "*cie*", 1, 2, "PRIMARY");

        Assert.assertNotNull(groups, "Failed to list the groups.");
        Assert.assertTrue(!groups.isEmpty() && groups.size() == 2, "Number of groups received in the response " +
                "is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers", "addGroups"}, groups = "addGroupsToUser")
    public void testUpdateGroupsOfUser() {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        try {
            realmService.getIdentityStore().updateGroupsOfUser(users.get(0).getUniqueUserId(), Arrays.asList(groups.get
                    (0).getUniqueGroupId(), groups.get(1).getUniqueGroupId()));
        } catch (IdentityStoreException e) {
            Assert.fail("Failed to update groups of user.");
        }
    }

    @Test(dependsOnGroups = {"addUsers", "addGroups"}, groups = "addUsersToGroup")
    public void testUpdateUsersOfGroup() {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        try {
            realmService.getIdentityStore().updateUsersOfGroup(groups.get(3).getUniqueGroupId(), Arrays.asList(users.get
                    (2).getUniqueUserId(), users.get(3).getUniqueUserId()));
        } catch (IdentityStoreException e) {
            Assert.fail("Failed to update groups of user.");
        }
    }

    @Test(dependsOnGroups = {"addGroupsToUser", "addUsersToGroup"})
    public void testGetGroupsOfUser() throws IdentityStoreException, UserNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<Group> groupsOfUser = realmService.getIdentityStore().getGroupsOfUser(users.get(0).getUniqueUserId());
        Assert.assertNotNull(groupsOfUser, "Failed to get the groups.");
        Assert.assertTrue(!groupsOfUser.isEmpty() && groupsOfUser.size() > 0, "Number of groups received in the " +
                "response is invalid.");
    }

    @Test(dependsOnGroups = {"addGroupsToUser", "addUsersToGroup"})
    public void testGetUsersOfGroup() throws IdentityStoreException, GroupNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<User> usersOfGroup = realmService.getIdentityStore().getUsersOfGroup(groups.get(3).getUniqueGroupId());
        Assert.assertNotNull(usersOfGroup, "Failed to get the users.");
        Assert.assertTrue(!usersOfGroup.isEmpty() && usersOfGroup.size() > 0, "Number of users received in the " +
                "response is invalid.");
    }

    @Test(dependsOnGroups = {"addGroupsToUser", "addUsersToGroup"})
    public void testIsUserInGroup() throws IdentityStoreException, UserNotFoundException, GroupNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        boolean isUserInGroup = realmService.getIdentityStore().isUserInGroup(users.get(0).getUniqueUserId(), groups
                .get(0).getUniqueGroupId());

        Assert.assertTrue(isUserInGroup, "Is user exists in group failed.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testGetClaims() throws IdentityStoreException, UserNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<Claim> claims = realmService.getIdentityStore().getClaimsOfUser(users.get(0).getUniqueUserId());
        Assert.assertNotNull(claims, "Failed to get the claims.");
        Assert.assertTrue(!claims.isEmpty() && claims.size() > 0, "Number of claims received in the " +
                "response is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testGetClaimFromMetaClaims() throws IdentityStoreException, UserNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<MetaClaim> metaClaims = Arrays.asList(
                new MetaClaim("http://wso2.org/claims", "http://wso2.org/claims/username"),
                new MetaClaim("http://wso2.org/claims", "http://wso2.org/claims/email"));

        List<Claim> claims = realmService.getIdentityStore().getClaimsOfUser(users.get(0).getUniqueUserId(),
                metaClaims);
        Assert.assertNotNull(claims, "Failed to get the claims.");
        Assert.assertTrue(!claims.isEmpty() && claims.size() == 2, "Number of claims received in the " +
                "response is invalid.");
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testUpdateUserClaims() throws UserNotFoundException {

        Assert.assertNotNull(realmService, "Failed to get realm service instance");

        List<Claim> claims = Arrays
                .asList(new Claim("http://wso2.org/claims", "http://wso2.org/claims/username", "lucifer"),
                        new Claim("http://wso2.org/claims", "http://wso2.org/claims/firstName", "UpdatedLucifer"),
                        new Claim("http://wso2.org/claims", "http://wso2.org/claims/email", "up.lucifer@wso2.com"));

        try {
            realmService.getIdentityStore().updateUserClaims(users.get(0).getUniqueUserId(), claims);
        } catch (IdentityStoreException e) {
            Assert.fail("Failed to update user claims.");
        }
    }

    @Test(dependsOnGroups = {"addUsers"})
    public void testAuthenticate() throws IdentityStoreException, UserNotFoundException, AuthenticationFailure {

        IdentityStore identityStore = realmService.getIdentityStore();

        Callback[] callbacks = new Callback[1];

        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        passwordCallback.setPassword(new char[]{'a', 'd', 'm', 'i', 'n'});
        callbacks[0] = passwordCallback;


        Claim claim = new Claim(TestConstants.LOCAL_CLAIM_DIALECT, TestConstants.CLAIM_USERNAME, "lucifer");

        identityStore.authenticate(claim, callbacks, "PRIMARY");
    }

}
