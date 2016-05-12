package org.wso2.carbon.security.connector.osgi;

import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;
import org.wso2.carbon.osgi.test.util.CarbonSysPropConfiguration;
import org.wso2.carbon.osgi.test.util.OSGiTestConfigurationUtils;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.AuthenticationFailure;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.CredentialStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.AuthorizationStore;
import org.wso2.carbon.security.caas.user.core.store.CredentialStore;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Carbon Security JDBC connector OSGi tests.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class JDBCConnectorTests {

    private static final String DEFAULT_USERNAME = "admin";
    private static final String DEFAULT_ROLE = "admin";
    private static final String DEFAULT_GROUP = "is";
    private static final String DEFAULT_USER_ID = "41dadd2aea6e11e59ce95e5517507c66";
    private static final String DEFAULT_ROLE_ID = "985b79ecfcdf11e586aa5e5517507c66";
    private static final String DEFAULT_GROUP_ID = "a422aa98ecf411e59ce95e5517507c66";
    private static final String DEFAULT_PERMISSION_ID = "f61a1c240df011e6a1483e1d05defe78";
    private static final String DEFAULT_IDENTITY_STORE = "JDBCIS1";
    private static final String DEFAULT_CREDENTIAL_STORE = "JDBCCS1";
    private static final String DEFAULT_AUTHORIZATION_STORE = "JDBCAS1";
    private static final Permission DEFAULT_PERMISSION = new Permission("root/resource/id", "add");

    @Inject
    private BundleContext bundleContext;

    @Inject
    private RealmService realmService;

    @Inject
    private CarbonServerInfo carbonServerInfo;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = new ArrayList<>();
        optionList.add(mavenBundle()
                .groupId("org.wso2.orbit.com.nimbusds")
                .artifactId("nimbus-jose-jwt")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("net.minidev.wso2")
                .artifactId("json-smart")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.datasources")
                .artifactId("org.wso2.carbon.datasource.core")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.jndi")
                .artifactId("org.wso2.carbon.jndi")
                .versionAsInProject());
        optionList.add(mavenBundle()
                               .groupId("org.wso2.carbon.messaging")
                               .artifactId("org.wso2.carbon.messaging")
                               .version("1.0.2"));
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.security.caas")
                .artifactId("org.wso2.carbon.security.caas")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.security.userstore")
                .artifactId("org.wso2.carbon.security.userstore.jdbc")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("commons-io.wso2")
                .artifactId("commons-io")
                .version("2.4.0.wso2v1"));
        optionList.add(mavenBundle()
                .groupId("com.zaxxer")
                .artifactId("HikariCP")
                .version("2.4.1"));
        optionList.add(mavenBundle()
                .groupId("com.h2database")
                .artifactId("h2")
                .version("1.4.191"));

        String currentDir = Paths.get("").toAbsolutePath().toString();
        Path carbonHome = Paths.get(currentDir, "target", "carbon-home");

        CarbonSysPropConfiguration sysPropConfiguration = new CarbonSysPropConfiguration();
        sysPropConfiguration.setCarbonHome(carbonHome.toString());
        sysPropConfiguration.setServerKey("carbon-security");
        sysPropConfiguration.setServerName("WSO2 Carbon Security Server");
        sysPropConfiguration.setServerVersion("1.0.0");

        optionList = OSGiTestConfigurationUtils.getConfiguration(optionList, sysPropConfiguration);

        return optionList.toArray(new Option[optionList.size()]);
    }

    /* Authentication flow */

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

        assertNotNull(authManager.authenticate(callbacks));
    }

    /* Authorization flow */

    @Test
    public void testIsUserAuthorizedValid() throws AuthorizationStoreException,
            IdentityStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        assertTrue(authorizationStore.isUserAuthorized(DEFAULT_USER_ID, DEFAULT_PERMISSION, DEFAULT_IDENTITY_STORE));
    }

    @Test
    public void testIsGroupAuthorizedValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        authorizationStore.isGroupAuthorized(DEFAULT_GROUP_ID, DEFAULT_IDENTITY_STORE, DEFAULT_PERMISSION);
    }

    @Test
    public void testAddNewRoleValid() throws AuthorizationStoreException {

        List<Permission> permissions = new ArrayList<>();
        permissions.add(new Permission.PermissionBuilder("root/resource/id", "add", DEFAULT_PERMISSION_ID,
                DEFAULT_AUTHORIZATION_STORE).build());

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        Role role = authorizationStore.addRole("test", permissions, DEFAULT_AUTHORIZATION_STORE);

        assertNotNull(role.getRoleId());
    }

    @Test
    public void testAddNewPermissionValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        Permission permission = authorizationStore
                .addPermission("root/resource/id", "delete", DEFAULT_AUTHORIZATION_STORE);

        assertNotNull(permission.getPermissionId());
    }

    @Test
    public void testIsUserInRoleValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        assertTrue(authorizationStore.isUserInRole(DEFAULT_USER_ID, DEFAULT_IDENTITY_STORE, DEFAULT_ROLE));
    }

    @Test
    public void testIsGroupInRoleValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        assertTrue(authorizationStore.isGroupInRole(DEFAULT_GROUP_ID, DEFAULT_IDENTITY_STORE, DEFAULT_ROLE));
    }

    @Test
    public void testGetUsersOfRole() throws AuthorizationStoreException, IdentityStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        assertNotNull(authorizationStore.getUsersOfRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE));
    }

    @Test
    public void testGetGroupsOfRole() throws AuthorizationStoreException, IdentityStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        assertNotNull(authorizationStore.getGroupsOfRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE));
    }

    @Test
    public void testDeletePermission() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        authorizationStore.deletePermission(new Permission
                .PermissionBuilder("root/resource/id", "action2", "e890c688135011e6a1483e1d05defe78",
                DEFAULT_AUTHORIZATION_STORE).build());
    }

    @Test
    public void testDeleteRoleValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();
        authorizationStore.deleteRole(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("7f8adbe6134c11e6a1483e1d05defe78")
                .setRoleName("role1")
                .build());
    }

    @Test
    public void testUpdateRolesInUserPutValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Role> roles = new ArrayList<>();
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("985b79ecfcdf11e586aa5e5517507c66")
                .setRoleName("admin")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("df813f5e105e11e6a1483e1d05defe78")
                .setRoleName("guest")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("70e2e088105f11e6a1483e1d05defe78")
                .setRoleName("general")
                .build());

        authorizationStore.updateRolesInUser(DEFAULT_USER_ID, DEFAULT_IDENTITY_STORE, roles);
    }

    @Test
    public void testUpdateRolesInUserPatchValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Role> roles = new ArrayList<>();
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("985b79ecfcdf11e586aa5e5517507c66")
                .setRoleName("admin")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("df813f5e105e11e6a1483e1d05defe78")
                .setRoleName("guest")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("70e2e088105f11e6a1483e1d05defe78")
                .setRoleName("general")
                .build());

        authorizationStore.updateRolesInUser(DEFAULT_USER_ID, DEFAULT_IDENTITY_STORE, roles, roles);
    }

    @Test
    public void testUpdateUsersInRolePutValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<User> users = new ArrayList<>();
        users.add(new User.UserBuilder()
                .setUserName("user1")
                .setUserId("b5572242139d11e6a1483e1d05defe78")
                .setTenantDomain("wso2.com")
                .setCredentialStoreId(DEFAULT_CREDENTIAL_STORE)
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());

        users.add(new User.UserBuilder()
                .setUserName("user2")
                .setUserId("b5572580139d11e6a1483e1d05defe78")
                .setTenantDomain("wso2.com")
                .setCredentialStoreId(DEFAULT_CREDENTIAL_STORE)
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());

        authorizationStore.updateUsersInRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, users);
    }

    @Test
    public void testUpdateUsersInRolePatchValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<User> users = new ArrayList<>();
        users.add(new User.UserBuilder()
                .setUserName("user1")
                .setUserId("b5572242139d11e6a1483e1d05defe78")
                .setTenantDomain("wso2.com")
                .setCredentialStoreId(DEFAULT_CREDENTIAL_STORE)
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());

        users.add(new User.UserBuilder()
                .setUserName("user2")
                .setUserId("b5572580139d11e6a1483e1d05defe78")
                .setTenantDomain("wso2.com")
                .setCredentialStoreId(DEFAULT_CREDENTIAL_STORE)
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());

        authorizationStore.updateUsersInRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, users);
    }

    @Test
    public void testUpdateRolesInGroupPutValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Role> roles = new ArrayList<>();
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("985b79ecfcdf11e586aa5e5517507c66")
                .setRoleName("admin")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("df813f5e105e11e6a1483e1d05defe78")
                .setRoleName("guest")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("70e2e088105f11e6a1483e1d05defe78")
                .setRoleName("general")
                .build());

        authorizationStore.updateRolesInGroup(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, roles);
    }

    @Test
    public void testUpdateRolesInGroupPatchValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Role> roles = new ArrayList<>();
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("985b79ecfcdf11e586aa5e5517507c66")
                .setRoleName("admin")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("df813f5e105e11e6a1483e1d05defe78")
                .setRoleName("guest")
                .build());
        roles.add(new Role.RoleBuilder()
                .setAuthorizationStoreId(DEFAULT_AUTHORIZATION_STORE)
                .setAuthorizationStore(authorizationStore)
                .setRoleId("70e2e088105f11e6a1483e1d05defe78")
                .setRoleName("general")
                .build());

        authorizationStore.updateRolesInGroup(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, roles, roles);
    }

    @Test
    public void testUpdateGroupsInRolePutValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Group> groups = new ArrayList<>();
        groups.add(new Group.GroupBuilder()
                .setGroupName("is")
                .setGroupId("a422aa98ecf411e59ce95e5517507c66")
                .setTenantDomain("wso2.com")
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());
        groups.add(new Group.GroupBuilder()
                .setGroupName("security")
                .setGroupId("16231aee15a711e6a1483e1d05defe78")
                .setTenantDomain("wso2.com")
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());

        authorizationStore.updateGroupsInRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, groups);
    }

    @Test
    public void testUpdateGroupsInRolePatchValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Group> groups = new ArrayList<>();
        groups.add(new Group.GroupBuilder()
                .setGroupName("is")
                .setGroupId("a422aa98ecf411e59ce95e5517507c66")
                .setTenantDomain("wso2.com")
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());
        groups.add(new Group.GroupBuilder()
                .setGroupName("security")
                .setGroupId("16231aee15a711e6a1483e1d05defe78")
                .setTenantDomain("wso2.com")
                .setIdentityStoreId(DEFAULT_IDENTITY_STORE)
                .setIdentityStore(realmService.getIdentityStore())
                .setAuthorizationStore(realmService.getAuthorizationStore())
                .build());

        authorizationStore.updateGroupsInRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, groups, groups);
    }

    @Test
    public void testUpdatePermissionsInRolePutValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Permission> permissions = new ArrayList<>();
        permissions.add(new Permission.PermissionBuilder("root/resource/id", "add", "f61a1c240df011e6a1483e1d05defe78",
                DEFAULT_AUTHORIZATION_STORE)
                .build());
        permissions.add(new Permission.PermissionBuilder("root/resource/id", "delete",
                "64335ff4106211e6a1483e1d05defe78", DEFAULT_AUTHORIZATION_STORE)
                .build());

        authorizationStore.updatePermissionsInRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, permissions);
    }

    @Test
    public void testUpdatePermissionsInRolePatchValid() throws AuthorizationStoreException {

        AuthorizationStore authorizationStore = realmService.getAuthorizationStore();

        List<Permission> permissions = new ArrayList<>();
        permissions.add(new Permission.PermissionBuilder("root/resource/id", "add", "f61a1c240df011e6a1483e1d05defe78",
                DEFAULT_AUTHORIZATION_STORE)
                .build());
        permissions.add(new Permission.PermissionBuilder("root/resource/id", "delete",
                "64335ff4106211e6a1483e1d05defe78", DEFAULT_AUTHORIZATION_STORE)
                .build());

        authorizationStore.updatePermissionsInRole(DEFAULT_ROLE_ID, DEFAULT_AUTHORIZATION_STORE, permissions,
                permissions);
    }

    /* Identity management flow */

    @Test
    public void testIsUserInGroupValid() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        assertTrue(identityStore.isUserInGroup(DEFAULT_USER_ID, DEFAULT_GROUP_ID, DEFAULT_IDENTITY_STORE));
    }

    @Test
    public void testGetUserFromUsername() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        User user  = identityStore.getUser(DEFAULT_USERNAME);
        assertNotNull(user);
    }

    @Test
    public void testGetUserFromUserId() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        User user  = identityStore.getUserFromId(DEFAULT_USER_ID, DEFAULT_IDENTITY_STORE);
        assertNotNull(user);
    }

    @Test
    public void testListUsers() throws IdentityStoreException {

        String filterPattern = "admin";

        IdentityStore identityStore = realmService.getIdentityStore();
        List<User> users = identityStore.listUsers(filterPattern, 0, 1);

        assertFalse(users.isEmpty());
    }

    @Test
    public void testGetUserClaimValues() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        Map<String, String> claims = identityStore.getUserAttributeValues(DEFAULT_USER_ID, DEFAULT_IDENTITY_STORE);

        assertFalse(claims.isEmpty());
    }

    @Test
    public void testGetUserClaimValuesFromURIs() throws IdentityStoreException {

        List<String> attributeNames = new ArrayList<>();
        attributeNames.add("firstName");

        IdentityStore identityStore = realmService.getIdentityStore();
        Map<String, String> claims = identityStore.getUserAttributeValues(DEFAULT_USER_ID, attributeNames,
                DEFAULT_IDENTITY_STORE);

        assertFalse(claims.isEmpty());
    }

    @Test
    public void testGetGroup() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        Group group = identityStore.getGroup(DEFAULT_GROUP);

        assertNotNull(group);
    }

    @Test
    public void testGetGroupFromId() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        Group group = identityStore.getGroupFromId(DEFAULT_GROUP_ID, DEFAULT_IDENTITY_STORE);

        assertNotNull(group);
    }

    @Test
    public void testListGroups() throws IdentityStoreException {

        String filterPattern = "is";

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Group> groups = identityStore.listGroups(filterPattern, 0, 1);

        assertFalse(groups.isEmpty());
    }

    @Test
    public void testGetGroupsOfUser() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<Group> groups = identityStore.getGroupsOfUser(DEFAULT_USER_ID, DEFAULT_IDENTITY_STORE);
        assertFalse(groups.isEmpty());
    }

    @Test
    public void testGetUsersOfGroup() throws IdentityStoreException {

        IdentityStore identityStore = realmService.getIdentityStore();
        List<User> users = identityStore.getUsersOfGroup(DEFAULT_GROUP_ID, DEFAULT_IDENTITY_STORE);
        assertFalse(users.isEmpty());
    }
}
