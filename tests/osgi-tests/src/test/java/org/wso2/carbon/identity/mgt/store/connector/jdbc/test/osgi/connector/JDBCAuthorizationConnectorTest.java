///*
// * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
// *
// * WSO2 Inc. licenses this file to you under the Apache License,
// * Version 2.0 (the "License"); you may not use this file except
// * in compliance with the License.
// * You may obtain a copy of the License at
// *
// * http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing,
// * software distributed under the License is distributed on an
// * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// * KIND, either express or implied. See the License for the
// * specific language governing permissions and limitations
// * under the License.
// */
//
//package org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.connector;
//
//import org.testng.Assert;
//import org.testng.annotations.Test;
//import org.wso2.carbon.identity.mgt.Action;
//import org.wso2.carbon.identity.mgt.Group;
//import org.wso2.carbon.identity.mgt.Permission;
//import org.wso2.carbon.identity.mgt.Resource;
//import org.wso2.carbon.identity.mgt.Role;
//import org.wso2.carbon.identity.mgt.User;
//import org.wso2.carbon.identity.mgt.connector.AuthorizationStoreConnector;
//import org.wso2.carbon.identity.mgt.connector.AuthorizationStoreConnectorFactory;
//import org.wso2.carbon.identity.mgt.connector.config.AuthorizationStoreConnectorConfig;
//import org.wso2.carbon.identity.mgt.exception.AuthorizationStoreException;
//import org.wso2.carbon.identity.mgt.exception.DomainException;
//import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
//import org.wso2.carbon.identity.mgt.exception.PermissionNotFoundException;
//import org.wso2.carbon.identity.mgt.exception.RoleNotFoundException;
//import org.wso2.carbon.identity.mgt.impl.JDBCUniqueIdResolver;
//import org.wso2.carbon.identity.mgt.resolver.UniqueIdResolver;
//import org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.JDBCConnectorTests;
//
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Properties;
//import javax.inject.Inject;
//
//
//public class JDBCAuthorizationConnectorTest extends JDBCConnectorTests {
//    private static final String DEFAULT_RESOURCE_NAME_ADD = "root/resource/new";
//    private static final String DEFAULT_ACTION_NAME_ADD = "newaction";
//    private static final String DEFAULT_ROLE_NAME_ADD = "newrole";
//
//    public static final String USER_UNIQUE_ID_1 = "5b19a9d5-9c49-4e29-9742-d02562cd371a";
//    public static final String USER_UNIQUE_ID_2 = "61b1c460-6da6-47d6-a19a-213f6cdc4607";
//    public static final String USER_UNIQUE_ID_3 = "2eddfa92-dd25-469a-9274-2fe140183814";
//    public static final String USER_UNIQUE_ID_4 = "9a601918-67de-44c9-abb5-f7b7aba25672";
//
//    public static final String GROUP_UNIQUE_ID_1 = "6cadeebd-f7af-4178-ad2e-4879e706b64b";
//    public static final String GROUP_UNIQUE_ID_2 = "849697e0-e88a-40b3-86ca-d5e3b81f1e7d";
//    public static final String GROUP_UNIQUE_ID_3 = "cb587488-d2b9-42b6-b059-3253049bb637";
//    public static final String GROUP_UNIQUE_ID_4 = "63c2ec5d-d235-4a59-b265-8c1216517223";
//
//    public static final String ROLE_UNIQUE_ID_1 = "eb9ba8c4-0436-4439-91dd-27694d01ed94";
//    public static final String ROLE_UNIQUE_ID_2 = "fb54ecc0-b3a8-42ad-b4e8-2200fa4fc590";
//    public static final String ROLE_UNIQUE_ID_3 = "3b6270cb-cdf1-4e8b-8027-066a6651a0c3";
//    public static final String ROLE_UNIQUE_ID_4 = "c9bc2c9f-f753-45bb-9a2d-66845dc7e1c9";
//
//    static final UniqueIdResolver UNIQUE_ID_RESOLVER = new JDBCUniqueIdResolver();
//
//    //This is initialized from a test
//    private static String addedPermissionId;
//    private static String addedRoleId;
//
//    @Inject
//    protected AuthorizationStoreConnectorFactory authorizationStoreConnectorFactory;
//
//    private static AuthorizationStoreConnector authorizationStoreConnector;
//
//    private void initConnector() throws IdentityStoreException, AuthorizationStoreException {
//        Assert.assertNotNull(authorizationStoreConnectorFactory);
//        authorizationStoreConnector = authorizationStoreConnectorFactory.getInstance();
//        Properties properties = new Properties();
//        properties.setProperty("dataSource", "WSO2_CARBON_DB");
//        properties.setProperty("databaseType", "MySQL");
//
//        AuthorizationStoreConnectorConfig authorizationStoreConnectorConfig =
//                new AuthorizationStoreConnectorConfig(DEFAULT_AUTHORIZATION_STORE, properties);
//
//        authorizationStoreConnector.init(DEFAULT_AUTHORIZATION_STORE, authorizationStoreConnectorConfig);
//    }
//
//    @Test(priority = 1)
//    public void testAddResource() throws AuthorizationStoreException, IdentityStoreException {
//
//        //As beforeClass is not supported, connector is initialized here
//        initConnector();
//        authorizationStoreConnector.addResource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_NAME_ADD, DEFAULT_USER_ID);
//        List<Resource.ResourceBuilder> resourceBuilders = authorizationStoreConnector.getResources
//                (DEFAULT_RESOURCE_NAME_ADD);
//        Assert.assertTrue(resourceBuilders.size() > 0);
//
//        Assert.assertTrue(resourceBuilders.stream().anyMatch(item -> (DEFAULT_NAMESPACE + Resource.DELIMITER +
//                DEFAULT_RESOURCE_NAME_ADD).equals(item.setAuthorizationStore(DEFAULT_AUTHORIZATION_STORE)
//                .build().getResourceString())));
//    }
//
//    @Test(priority = 2)
//    public void testAddAction() throws IdentityStoreException, AuthorizationStoreException {
//
//        authorizationStoreConnector.addAction(DEFAULT_NAMESPACE, DEFAULT_ACTION_NAME_ADD);
//        List<Action.ActionBuilder> actionBuilders = authorizationStoreConnector.getActions
//                (DEFAULT_ACTION_NAME_ADD);
//        Assert.assertTrue(actionBuilders.size() > 0);
//
//        Assert.assertTrue(actionBuilders.stream().anyMatch(item -> (DEFAULT_NAMESPACE + Action.DELIMITER +
//                DEFAULT_ACTION_NAME_ADD).equals(item.setAuthorizationStore(DEFAULT_AUTHORIZATION_STORE)
//                .build().getActionString())));
//    }
//
//    @Test(priority = 3)
//    public void testAddPermission() throws IdentityStoreException, AuthorizationStoreException,
//                                           PermissionNotFoundException {
//
//        Resource resource = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_NAME_ADD, DEFAULT_USER_ID);
//        Action action = new Action(DEFAULT_NAMESPACE, DEFAULT_ACTION_NAME_ADD);
//        Permission.PermissionBuilder permissionBuilderAdd = authorizationStoreConnector.addPermission(resource,
//                                                                                                      action);
//        Permission permissionAdd = permissionBuilderAdd.build();
//        Permission.PermissionBuilder permissionBuilder = authorizationStoreConnector.getPermission(resource, action);
//
//        Permission permission = permissionBuilder.build();
//        Assert.assertEquals(permission.getResource().getOwner().getUserId(), DEFAULT_USER_ID);
//        Assert.assertEquals(permissionAdd.getPermissionId(), permission.getPermissionId());
//        addedPermissionId = permissionAdd.getPermissionId();
//    }
//
//    @Test(priority = 4)
//    public void testAddRole() throws IdentityStoreException, AuthorizationStoreException, RoleNotFoundException {
//
//        List<Permission> permissions = new ArrayList<>();
//
//        //Added from the above test
//        Resource resource1 = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_NAME_ADD, DEFAULT_USER_ID);
//        Action action1 = new Action(DEFAULT_NAMESPACE, DEFAULT_ACTION_NAME_ADD);
//        permissions.add(new Permission.PermissionBuilder(resource1, action1, addedPermissionId,
//                DEFAULT_AUTHORIZATION_STORE).build());
//
//        //Added from the test resources
//        Resource resource2 = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_PATH, DEFAULT_USER_ID);
//        Action action2 = new Action(DEFAULT_NAMESPACE, "add");
//        permissions.add(new Permission.PermissionBuilder(resource2, action2, "f61a1c240df011e6a1483e1d05defe78",
//                DEFAULT_AUTHORIZATION_STORE).build());
//
//        Resource resource3 = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_PATH, DEFAULT_USER_ID);
//        Action action3 = new Action(DEFAULT_NAMESPACE, "delete");
//        permissions.add(new Permission.PermissionBuilder(resource3, action3, "64335ff4106211e6a1483e1d05defe78",
//                DEFAULT_AUTHORIZATION_STORE).build());
//
//        Role.RoleBuilder roleBuilder = authorizationStoreConnector.addRole(DEFAULT_ROLE_NAME_ADD, permissions);
//        Role role = roleBuilder.setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//
//        Role roleRetrieved = authorizationStoreConnector.getRole(DEFAULT_ROLE_NAME_ADD)
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        Assert.assertEquals(roleRetrieved.getRoleId(), role.getRoleId());
//        addedRoleId = role.getRoleId();
//
//        List<Permission.PermissionBuilder> permissionsForRole = authorizationStoreConnector.getPermissionsForRole
//                (addedRoleId, resource1);
//
//        Assert.assertTrue(permissionsForRole.stream().anyMatch(item -> (DEFAULT_RESOURCE_NAME_ADD +
// DEFAULT_NAMESPACE +
//                Action.DELIMITER + DEFAULT_ACTION_NAME_ADD).equals(item.build().getPermissionString())));
//
//        permissionsForRole = authorizationStoreConnector.getPermissionsForRole(addedRoleId, resource2);
//
//        Assert.assertTrue(permissionsForRole.stream().anyMatch(item -> (DEFAULT_RESOURCE_PATH + DEFAULT_NAMESPACE +
//                Action.DELIMITER + "add").equals(item.build().getPermissionString())));
//
//        permissionsForRole = authorizationStoreConnector.getPermissionsForRole(addedRoleId, resource3);
//
//        Assert.assertTrue(permissionsForRole.stream().anyMatch(item -> (DEFAULT_RESOURCE_PATH + DEFAULT_NAMESPACE +
//                Action.DELIMITER + "delete").equals(item.build().getPermissionString())));
//
//        permissionsForRole = authorizationStoreConnector.getPermissionsForRole(addedRoleId, action1);
//
//        Assert.assertTrue(permissionsForRole.stream().anyMatch(item -> (DEFAULT_RESOURCE_NAME_ADD +
// DEFAULT_NAMESPACE +
//                Action.DELIMITER + DEFAULT_ACTION_NAME_ADD).equals(item.build().getPermissionString())));
//
//        permissionsForRole = authorizationStoreConnector.getPermissionsForRole(addedRoleId, action2);
//
//        Assert.assertTrue(permissionsForRole.stream().anyMatch(item -> (DEFAULT_RESOURCE_PATH + DEFAULT_NAMESPACE +
//                Action.DELIMITER + "add").equals(item.build().getPermissionString())));
//
//        permissionsForRole = authorizationStoreConnector.getPermissionsForRole(addedRoleId, action3);
//
//        Assert.assertTrue(permissionsForRole.stream().anyMatch(item -> (DEFAULT_RESOURCE_PATH + DEFAULT_NAMESPACE +
//                Action.DELIMITER + "delete").equals(item.build().getPermissionString())));
//
//    }
//
//    @Test(priority = 5)
//    public void testUpdateUsersInRolePut() throws DomainException, AuthorizationStoreException {
//
//        List<User> userList = new ArrayList<>();
//        User user1 = new User.UserBuilder()
//                .setUserId(USER_UNIQUE_ID_1)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userList.add(user1);
//
//        User user2 = new User.UserBuilder()
//                .setUserId(USER_UNIQUE_ID_2)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userList.add(user2);
//
//        authorizationStoreConnector.updateUsersInRole(addedRoleId, userList);
//
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_1,
//                DEFAULT_ROLE_NAME_ADD));
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_2,
//                DEFAULT_ROLE_NAME_ADD));
//
//        List<Role.RoleBuilder> rolesForGroup = authorizationStoreConnector
//                .getRolesForUser(USER_UNIQUE_ID_1);
//        Assert.assertTrue(rolesForGroup.stream().
//                anyMatch(item -> DEFAULT_ROLE_NAME_ADD.equals(item.build().getName())));
//
//        rolesForGroup = authorizationStoreConnector.getRolesForUser(USER_UNIQUE_ID_2);
//        Assert.assertTrue(rolesForGroup.stream().
//                anyMatch(item -> DEFAULT_ROLE_NAME_ADD.equals(item.build().getName())));
//    }
//
//
//    @Test(priority = 6)
//    public void testUpdateUsersInRolePatch() throws DomainException, AuthorizationStoreException {
//
//        List<User> userListRemove = new ArrayList<>();
//        User user1 = new User.UserBuilder()
//                .setUserId(USER_UNIQUE_ID_1)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userListRemove.add(user1);
//
//        List<User> userListAdd = new ArrayList<>();
//        User user2 = new User.UserBuilder()
//                .setUserId(USER_UNIQUE_ID_3)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userListAdd.add(user2);
//
//        User user3 = new User.UserBuilder()
//                .setUserId(USER_UNIQUE_ID_4)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userListAdd.add(user3);
//
//        authorizationStoreConnector.updateUsersInRole(addedRoleId, userListAdd, userListRemove);
//
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_3,
//                DEFAULT_ROLE_NAME_ADD));
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_4,
//                DEFAULT_ROLE_NAME_ADD));
//        Assert.assertFalse(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_1,
//                DEFAULT_ROLE_NAME_ADD));
//        List<User.UserBuilder> usersOfRole = authorizationStoreConnector.getUsersOfRole(addedRoleId);
//        //2 users added previously. 2 users are added here and removed 1
//        Assert.assertEquals(usersOfRole.size(), 3);
//    }
//
//    @Test(priority = 7)
//    public void testUpdateGroupsInRolePut() throws DomainException, AuthorizationStoreException {
//
//        List<Group> userList = new ArrayList<>();
//        Group user1 = new Group.GroupBuilder()
//                .setGroupId(GROUP_UNIQUE_ID_1)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userList.add(user1);
//
//        Group user2 = new Group.GroupBuilder()
//                .setGroupId(GROUP_UNIQUE_ID_2)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userList.add(user2);
//
//        authorizationStoreConnector.updateGroupsInRole(addedRoleId, userList);
//
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_1,
//                DEFAULT_ROLE_NAME_ADD));
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_2,
//                DEFAULT_ROLE_NAME_ADD));
//
//        List<Role.RoleBuilder> rolesForGroup = authorizationStoreConnector
//                .getRolesForGroup(GROUP_UNIQUE_ID_1);
//        Assert.assertTrue(rolesForGroup.stream().
//                anyMatch(item -> DEFAULT_ROLE_NAME_ADD.equals(item.build().getName())));
//
//        rolesForGroup = authorizationStoreConnector.getRolesForGroup(GROUP_UNIQUE_ID_2);
//        Assert.assertTrue(rolesForGroup.stream().
//                anyMatch(item -> DEFAULT_ROLE_NAME_ADD.equals(item.build().getName())));
//
//    }
//
//
//    @Test(priority = 8)
//    public void testUpdateGroupsInRolePatch() throws DomainException, AuthorizationStoreException {
//
//        List<Group> userListRemove = new ArrayList<>();
//        Group user1 = new Group.GroupBuilder()
//                .setGroupId(GROUP_UNIQUE_ID_1)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userListRemove.add(user1);
//
//        List<Group> userListAdd = new ArrayList<>();
//        Group user2 = new Group.GroupBuilder()
//                .setGroupId(GROUP_UNIQUE_ID_3)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userListAdd.add(user2);
//
//        Group user3 = new Group.GroupBuilder()
//                .setGroupId(GROUP_UNIQUE_ID_4)
//                .setAuthorizationStore(authorizationService.getAuthorizationStore())
//                .setIdentityStore(realmService.getIdentityStore()).build();
//        userListAdd.add(user3);
//
//        authorizationStoreConnector.updateGroupsInRole(addedRoleId, userListAdd, userListRemove);
//
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_3,
//                DEFAULT_ROLE_NAME_ADD));
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_4,
//                DEFAULT_ROLE_NAME_ADD));
//        Assert.assertFalse(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_1,
//                DEFAULT_ROLE_NAME_ADD));
//        List<Group.GroupBuilder> groupsOfRole = authorizationStoreConnector.getGroupsOfRole(addedRoleId);
//
//        //2 groups added previously. 2 groups are added here and removed 1
//        Assert.assertEquals(groupsOfRole.size(), 3);
//    }
//
//    @Test(priority = 9)
//    public void testUpdateRolesInUserPut() throws AuthorizationStoreException {
//
//        List<Role> roles = new ArrayList<>();
//        Role role1 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_1).setRoleName("role6")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        roles.add(role1);
//        Role role2 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_2).setRoleName("role7")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        roles.add(role2);
//        authorizationStoreConnector.updateRolesInUser(USER_UNIQUE_ID_1, roles);
//        List<Role.RoleBuilder> rolesForUser = authorizationStoreConnector.getRolesForUser(USER_UNIQUE_ID_1);
//        Assert.assertEquals(rolesForUser.size(), 2);
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_1, "role6"));
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_1, "role7"));
//    }
//
//    @Test(priority = 10)
//    public void testUpdateRolesInUserPatch() throws AuthorizationStoreException {
//
//        List<Role> rolesToAdd = new ArrayList<>();
//        Role role1 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_3).setRoleName("role8")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        rolesToAdd.add(role1);
//        Role role2 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_4).setRoleName("role9")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        rolesToAdd.add(role2);
//
//        List<Role> rolesToRemove = new ArrayList<>();
//        Role role3 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_1).setRoleName("role6")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        rolesToRemove.add(role3);
//        authorizationStoreConnector.updateRolesInUser(USER_UNIQUE_ID_1, rolesToAdd, rolesToRemove);
//        List<Role.RoleBuilder> rolesForUser = authorizationStoreConnector.getRolesForUser(USER_UNIQUE_ID_1);
//        Assert.assertEquals(rolesForUser.size(), 3);
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_1, "role8"));
//        Assert.assertTrue(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_1, "role9"));
//        Assert.assertFalse(authorizationStoreConnector.isUserInRole(USER_UNIQUE_ID_1, "role6"));
//    }
//
//    @Test(priority = 11)
//    public void testUpdateRolesInGroupPut() throws AuthorizationStoreException {
//
//        List<Role> roles = new ArrayList<>();
//        Role role1 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_1).setRoleName("role6")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        roles.add(role1);
//        Role role2 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_2).setRoleName("role7")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        roles.add(role2);
//        authorizationStoreConnector.updateRolesInGroup(GROUP_UNIQUE_ID_1, roles);
//        List<Role.RoleBuilder> rolesForUser = authorizationStoreConnector.getRolesForGroup(GROUP_UNIQUE_ID_1);
//        Assert.assertEquals(rolesForUser.size(), 2);
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_1, "role6"));
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_1, "role7"));
//    }
//
//    @Test(priority = 12)
//    public void testUpdateRolesInGroupPatch() throws AuthorizationStoreException {
//
//        List<Role> rolesToAdd = new ArrayList<>();
//        Role role1 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_3).setRoleName("role8")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        rolesToAdd.add(role1);
//        Role role2 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_4).setRoleName("role9")
//                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        rolesToAdd.add(role2);
//
//        List<Role> rolesToRemove = new ArrayList<>();
//        Role role3 = new Role.RoleBuilder().setRoleId(ROLE_UNIQUE_ID_1).setRoleName("role6")
//                                           .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE).build();
//        rolesToRemove.add(role3);
//        authorizationStoreConnector.updateRolesInGroup(GROUP_UNIQUE_ID_1, rolesToAdd, rolesToRemove);
//        List<Role.RoleBuilder> rolesForUser = authorizationStoreConnector.getRolesForGroup(GROUP_UNIQUE_ID_1);
//        Assert.assertEquals(rolesForUser.size(), 3);
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_1, "role8"));
//        Assert.assertTrue(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_1, "role9"));
//        Assert.assertFalse(authorizationStoreConnector.isGroupInRole(GROUP_UNIQUE_ID_1, "role6"));
//    }
//
//    @Test(priority = 30)
//    public void testDeleteResource() throws AuthorizationStoreException {
//
//        Resource resource = new Resource.ResourceBuilder().setUserId(DEFAULT_USER_ID)
//                                                          .setResourceId(DEFAULT_RESOURCE_NAME_ADD)
//                                                          .setResourceNamespace(DEFAULT_NAMESPACE)
//                                                          .setAuthorizationStore(DEFAULT_AUTHORIZATION_STORE).build();
//        authorizationStoreConnector.deleteResource(resource);
//        List<Resource.ResourceBuilder> resourceBuilders = authorizationStoreConnector.getResources
//                (DEFAULT_RESOURCE_NAME_ADD);
//        Assert.assertEquals(resourceBuilders.size(), 0);
//    }
//
//    @Test(priority = 31)
//    public void testDeleteAction() throws AuthorizationStoreException {
//
//        Action action = new Action.ActionBuilder().setAction(DEFAULT_ACTION_NAME_ADD).setActionNamespace
//                (DEFAULT_NAMESPACE).setAuthorizationStore(DEFAULT_AUTHORIZATION_STORE).build();
//        authorizationStoreConnector.deleteAction(action);
//        List<Action.ActionBuilder> actionBuilders = authorizationStoreConnector.getActions(DEFAULT_RESOURCE_NAME_ADD);
//        Assert.assertEquals(actionBuilders.size(), 0);
//    }
//
//    @Test(priority = 32, expectedExceptions = Exception.class,
//            expectedExceptionsMessageRegExp = "No role found for the given name.*")
//    public void testDeleteRole() throws AuthorizationStoreException, RoleNotFoundException {
//
//        authorizationStoreConnector.deleteRole(addedRoleId);
//        authorizationStoreConnector.getRole(addedRoleId);
//    }
//
//    @Test(priority = 32, expectedExceptions = Exception.class,
//            expectedExceptionsMessageRegExp = "No permission found  for the given name.*")
//    public void testDeletePermission() throws AuthorizationStoreException, PermissionNotFoundException {
//
//        authorizationStoreConnector.deletePermission(addedPermissionId);
//        Resource resource = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_NAME_ADD, DEFAULT_USER_ID);
//        Action action = new Action(DEFAULT_NAMESPACE, DEFAULT_ACTION_NAME_ADD);
//        authorizationStoreConnector.getPermission(resource, action);
//    }
//
//}
