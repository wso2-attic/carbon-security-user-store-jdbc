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

package org.wso2.carbon.security.userstore.jdbc.test.osgi.connector;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.security.caas.user.core.bean.Action;
import org.wso2.carbon.security.caas.user.core.bean.Permission;
import org.wso2.carbon.security.caas.user.core.bean.Resource;
import org.wso2.carbon.security.caas.user.core.bean.Role;
import org.wso2.carbon.security.caas.user.core.config.AuthorizationStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.AuthorizationStoreException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.PermissionNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.RoleNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnector;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.test.osgi.JDBCConnectorTests;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.inject.Inject;

public class JDBCAuthorizationConnectorTest extends JDBCConnectorTests {
    private static final String DEFAULT_RESOURCE_NAME_ADD = "root/resource/new";
    private static final String DEFAULT_ACTION_NAME_ADD = "newaction";
    private static final String DEFAULT_ROLE_NAME_ADD = "newrole";

    //This is initialized from a test
    private static String addedPermissionId;

    @Inject
    protected AuthorizationStoreConnectorFactory authorizationStoreConnectorFactory;

    private static AuthorizationStoreConnector authorizationStoreConnector;

    private void initConnector() throws IdentityStoreException, AuthorizationStoreException {
        Assert.assertNotNull(authorizationStoreConnectorFactory);
        authorizationStoreConnector = authorizationStoreConnectorFactory.getInstance();
        AuthorizationStoreConnectorConfig authorizationStoreConnectorConfig = new AuthorizationStoreConnectorConfig();
        authorizationStoreConnectorConfig.setConnectorId(DEFAULT_AUTHORIZATION_STORE);
        authorizationStoreConnectorConfig.setConnectorType("JDBCAuthorizationStore");
        Properties properties = new Properties();
        properties.setProperty("dataSource", "WSO2_CARBON_DB");
        properties.setProperty("databaseType", "MySQL");
        authorizationStoreConnectorConfig.setProperties(properties);
        authorizationStoreConnector.init(authorizationStoreConnectorConfig);
    }

    @Test(priority = 1)
    public void testAddResource() throws AuthorizationStoreException, IdentityStoreException {

        //As beforeClass is not supported, connector is initialized here
        initConnector();
        authorizationStoreConnector.addResource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_NAME_ADD, DEFAULT_USER_ID);
        List<Resource.ResourceBuilder> resourceBuilders = authorizationStoreConnector.getResources
                (DEFAULT_RESOURCE_NAME_ADD);
        Assert.assertTrue(resourceBuilders.size() > 0);

        Assert.assertTrue(resourceBuilders.stream().anyMatch(item -> (DEFAULT_NAMESPACE + Resource.DELIMITER +
                DEFAULT_RESOURCE_NAME_ADD).equals(item.setAuthorizationStoreConnectorId(DEFAULT_AUTHORIZATION_STORE)
                .build().getResourceString())));
    }

    @Test(priority = 2)
    public void testAddAction() throws IdentityStoreException, AuthorizationStoreException {

        authorizationStoreConnector.addAction(DEFAULT_NAMESPACE, DEFAULT_ACTION_NAME_ADD);
        List<Action.ActionBuilder> actionBuilders = authorizationStoreConnector.getActions
                (DEFAULT_ACTION_NAME_ADD);
        Assert.assertTrue(actionBuilders.size() > 0);

        Assert.assertTrue(actionBuilders.stream().anyMatch(item -> (DEFAULT_NAMESPACE + Action.DELIMITER +
                DEFAULT_ACTION_NAME_ADD).equals(item.setAuthorizationStore(DEFAULT_AUTHORIZATION_STORE)
                .build().getActionString())));
    }

    @Test(priority = 3)
    public void testAddPermission() throws IdentityStoreException, AuthorizationStoreException,
            PermissionNotFoundException {

        Resource resource = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_NAME_ADD, DEFAULT_USER_ID);
        Action action = new Action(DEFAULT_NAMESPACE, DEFAULT_ACTION_NAME_ADD);
        Permission.PermissionBuilder permissionBuilderAdd = authorizationStoreConnector.addPermission(resource, action);
        Permission permissionAdd = permissionBuilderAdd.build();
        Permission.PermissionBuilder permissionBuilder = authorizationStoreConnector.getPermission(resource, action);

        Permission permission = permissionBuilder.build();
        Assert.assertEquals(permission.getResource().getOwnerId(), DEFAULT_USER_ID);
        Assert.assertEquals(permissionAdd.getPermissionId(), permission.getPermissionId());
        addedPermissionId = permissionAdd.getPermissionId();
    }

    @Test(priority = 4)
    public void testAddRole() throws IdentityStoreException, AuthorizationStoreException, RoleNotFoundException {

        List<Permission> permissions = new ArrayList<>();

        //Added from the above test
        Resource resource1 = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_NAME_ADD, DEFAULT_USER_ID);
        Action action1 = new Action(DEFAULT_NAMESPACE, DEFAULT_ACTION_NAME_ADD);
        permissions.add(new Permission.PermissionBuilder(resource1, action1, addedPermissionId,
                DEFAULT_AUTHORIZATION_STORE).build());

        //Added from the test resources
        Resource resource2 = new Resource(DEFAULT_NAMESPACE, "root/resource/id", DEFAULT_USER_ID);
        Action action2 = new Action(DEFAULT_NAMESPACE, "add");
        permissions.add(new Permission.PermissionBuilder(resource2, action2, "f61a1c240df011e6a1483e1d05defe78",
                DEFAULT_AUTHORIZATION_STORE).build());

        Resource resource3 = new Resource(DEFAULT_NAMESPACE, "root/resource/id", DEFAULT_USER_ID);
        Action action3 = new Action(DEFAULT_NAMESPACE, "delete");
        permissions.add(new Permission.PermissionBuilder(resource3, action3, "64335ff4106211e6a1483e1d05defe78",
                DEFAULT_AUTHORIZATION_STORE).build());

        Role.RoleBuilder roleBuilder = authorizationStoreConnector.addRole(DEFAULT_ROLE_NAME_ADD, permissions);
        Role role = roleBuilder.setAuthorizationStoreConnectorId(DEFAULT_AUTHORIZATION_STORE).build();

        Role roleRetrieved = authorizationStoreConnector.getRole(DEFAULT_ROLE_NAME_ADD)
                .setAuthorizationStoreConnectorId(DEFAULT_AUTHORIZATION_STORE).build();
        Assert.assertEquals(roleRetrieved.getRoleId(), role.getRoleId());
    }

}