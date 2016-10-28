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

package org.wso2.carbon.security.userstore.jdbc.test.osgi.connector.privileged;

import org.ops4j.pax.exam.util.Filter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.user.mgt.store.connector.PrivilegedIdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.privileged.connector.factory.JDBCPrivilegedIdentityStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.test.osgi.JDBCConnectorTests;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.inject.Inject;

public class JDBCPrivilegedIdentityConnectorTests extends JDBCConnectorTests {

    @Inject
    @Filter("(connector-type=JDBCPrivilegedIdentityStore)")
    protected IdentityStoreConnectorFactory identityStoreConnectorFactory;

    private static PrivilegedIdentityStoreConnector privilegedIdentityStoreConnector;

    private void initConnector() throws IdentityStoreException {
        Assert.assertNotNull(identityStoreConnectorFactory);
        Assert.assertTrue(identityStoreConnectorFactory instanceof JDBCPrivilegedIdentityStoreConnectorFactory);
        privilegedIdentityStoreConnector = (PrivilegedIdentityStoreConnector)
                identityStoreConnectorFactory.getConnector();
        IdentityStoreConnectorConfig identityStoreConnectorConfig = new IdentityStoreConnectorConfig();
        identityStoreConnectorConfig.setConnectorId("JDBCIS1");
        identityStoreConnectorConfig.setConnectorType("JDBCPrivilegedIdentityStore");
        identityStoreConnectorConfig.setDomainName("carbon");
        List<String> uniqueAttributes = new ArrayList<>();
        uniqueAttributes.add("username");
        uniqueAttributes.add("email");
        identityStoreConnectorConfig.setUniqueAttributes(uniqueAttributes);
        List<String> otherAttributes = new ArrayList<>();
        otherAttributes.add("firstName");
        otherAttributes.add("lastName");
        identityStoreConnectorConfig.setOtherAttributes(otherAttributes);
        Properties properties = new Properties();
        properties.setProperty("dataSource", "WSO2_CARBON_DB");
        properties.setProperty("hashAlgorithm", "SHA256");
        properties.setProperty("databaseType", "MySQL");
        properties.setProperty("connectorUserId", "username");
        properties.setProperty("connectorGroupId", "groupname");
        identityStoreConnectorConfig.setProperties(properties);
        privilegedIdentityStoreConnector.init(identityStoreConnectorConfig);
    }

    @Test(priority = 2)
    public void testAddUser() throws IdentityStoreException {

        //As beforeClass is not supported, connector is initialized here
        initConnector();

        List<Attribute> attributes = new ArrayList<>();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("username");
        attribute1.setAttributeValue("maduranga");
        attributes.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("email");
        attribute2.setAttributeValue("maduranga@wso2.com");
        attributes.add(attribute2);
        Attribute attribute3 = new Attribute();
        attribute3.setAttributeName("firstname");
        attribute3.setAttributeValue("Maduranga");
        attributes.add(attribute3);
        Attribute attribute4 = new Attribute();
        attribute4.setAttributeName("lastname");
        attribute4.setAttributeValue("Siriwardena");
        attributes.add(attribute4);

        privilegedIdentityStoreConnector.addUser(attributes);

        List<Attribute> attributesRetrieved = privilegedIdentityStoreConnector.getUserAttributeValues("maduranga");
        Assert.assertNotNull(attributesRetrieved);
        Assert.assertTrue(attributesRetrieved.size() == 4);
        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributeMap.get("username"), "maduranga");
        Assert.assertEquals(attributeMap.get("email"), "maduranga@wso2.com");
        Assert.assertEquals(attributeMap.get("firstname"), "Maduranga");
        Assert.assertEquals(attributeMap.get("lastname"), "Siriwardena");
    }

    @Test(priority = 3)
    public void testAddGroup() throws IdentityStoreException {

        initConnector();

        List<Attribute> attributes = new ArrayList<>();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("groupname");
        attribute1.setAttributeValue("engineering");
        attributes.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("reportsto");
        attribute2.setAttributeValue("director@wso2.com");
        attributes.add(attribute2);

        privilegedIdentityStoreConnector.addGroup(attributes);

        List<Attribute> attributeRetrieved = privilegedIdentityStoreConnector.getGroupAttributeValues("engineering");
        Assert.assertNotNull(attributeRetrieved);
        Assert.assertEquals(attributeRetrieved.size(), 2);
    }

    @Test(priority = 4)
    public void testGroupsOfUserPut() throws IdentityStoreException {

        initConnector();

        List<String> groups = new ArrayList();
        groups.add("engineering");

        privilegedIdentityStoreConnector.updateGroupsOfUser("maduranga", groups);
        List<Group.GroupBuilder> groupBuilders = privilegedIdentityStoreConnector.getGroupBuildersOfUser("maduranga");
        Assert.assertEquals(groupBuilders.size(), 1);
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("maduranga", "engineering"));

        groups = new ArrayList();
        //These groups are added from the test data set
        groups.add("is");
        groups.add("sales");

        privilegedIdentityStoreConnector.updateGroupsOfUser("maduranga", groups);

        groupBuilders = privilegedIdentityStoreConnector.getGroupBuildersOfUser("maduranga");
        Assert.assertEquals(groupBuilders.size(), 2);
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("maduranga", "is"));
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("maduranga", "sales"));
    }

    @Test(priority = 5)
    public void testGroupsOfUserPatch() throws IdentityStoreException {

        initConnector();

        List<String> groupsToAdd = new ArrayList();
        groupsToAdd.add("engineering");

        List<String> groupsToRemove = new ArrayList();
        groupsToRemove.add("sales");

        privilegedIdentityStoreConnector.updateGroupsOfUser("maduranga", groupsToAdd, groupsToRemove);

        List<Group.GroupBuilder> groupBuilders = privilegedIdentityStoreConnector.getGroupBuildersOfUser("maduranga");

        Assert.assertEquals(groupBuilders.size(), 2);
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("maduranga", "is"));
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("maduranga", "engineering"));
    }

    @Test(priority = 6)
    public void testUsersOfGroupPut() throws IdentityStoreException {

        initConnector();

        List<String> users = new ArrayList();
        users.add("darshana");
        users.add("thanuja");

        privilegedIdentityStoreConnector.updateUsersOfGroup("engineering", users);

        List<User.UserBuilder> groupBuilders = privilegedIdentityStoreConnector.getUserBuildersOfGroup("engineering");

        Assert.assertEquals(groupBuilders.size(), 2);
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("darshana", "engineering"));
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("thanuja", "engineering"));
    }

    @Test(priority = 7)
    public void testUsersOfGroupPatch() throws IdentityStoreException {

        initConnector();

        List<String> usersToAdd = new ArrayList();
        usersToAdd.add("maduranga");

        List<String> usersToRemove = new ArrayList();
        usersToRemove.add("darshana");

        privilegedIdentityStoreConnector.updateUsersOfGroup("engineering", usersToAdd, usersToRemove);

        List<User.UserBuilder> groupBuilders = privilegedIdentityStoreConnector.getUserBuildersOfGroup("engineering");

        Assert.assertEquals(groupBuilders.size(), 2);
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("thanuja", "engineering"));
        Assert.assertTrue(privilegedIdentityStoreConnector.isUserInGroup("maduranga", "engineering"));
    }

    @Test(priority = 8)
    public void testUpdateUserAttributesPut() throws IdentityStoreException {

        initConnector();

        List<Attribute> attributesToUpdate = new ArrayList();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("username");
        attribute1.setAttributeValue("maduranga1");
        attributesToUpdate.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("email");
        attribute2.setAttributeValue("maduranga1@wso2.com");
        attributesToUpdate.add(attribute2);
        Attribute attribute3 = new Attribute();
        attribute3.setAttributeName("firstname");
        attribute3.setAttributeValue("Maduranga1");
        attributesToUpdate.add(attribute3);

        privilegedIdentityStoreConnector.updateUserAttributes("maduranga", attributesToUpdate);

        List<Attribute> attributesRetrieved = privilegedIdentityStoreConnector.getUserAttributeValues("maduranga1");

        Assert.assertEquals(attributesRetrieved.size(), 3);

        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributeMap.get("username"), "maduranga1");
        Assert.assertEquals(attributeMap.get("email"), "maduranga1@wso2.com");
        Assert.assertEquals(attributeMap.get("firstname"), "Maduranga1");
    }

    @Test(priority = 9)
    public void testUpdateUserAttributesPatch() throws IdentityStoreException {

        initConnector();

        List<Attribute> attributesToUpdate = new ArrayList();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("username");
        attribute1.setAttributeValue("maduranga");
        attributesToUpdate.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("email");
        attribute2.setAttributeValue("maduranga@wso2.com");
        attributesToUpdate.add(attribute2);
        Attribute attribute3 = new Attribute();
        attribute3.setAttributeName("lastname");
        attribute3.setAttributeValue("Siriwardena1");
        attributesToUpdate.add(attribute3);

        List<Attribute> attributesToDelete = new ArrayList();
        Attribute attribute5 = new Attribute();
        attribute5.setAttributeName("firstname");
        attribute5.setAttributeValue("Maduranga1");
        attributesToDelete.add(attribute5);

        privilegedIdentityStoreConnector.updateUserAttributes("maduranga1", attributesToUpdate, attributesToDelete);

        List<Attribute> attributesRetrieved = privilegedIdentityStoreConnector.getUserAttributeValues("maduranga");

        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributesRetrieved.size(), 3);
        Assert.assertEquals(attributeMap.get("username"), "maduranga");
        Assert.assertEquals(attributeMap.get("email"), "maduranga@wso2.com");
        Assert.assertEquals(attributeMap.get("lastname"), "Siriwardena1");
    }

    //TODO change the expectedExceptions to UserNotFoundException
    @Test(priority = 10, expectedExceptions = {Exception.class}, expectedExceptionsMessageRegExp = "User not found.*")
    public void testDeleteUser() throws UserNotFoundException, IdentityStoreException {

        initConnector();
        privilegedIdentityStoreConnector.deleteUser("maduranga");
        privilegedIdentityStoreConnector.getUserBuilder("username", "maduranga");
    }

    //TODO change the expectedExceptions to GroupNotFoundException
    @Test(priority = 11, expectedExceptions = {Exception.class}, expectedExceptionsMessageRegExp = "Group not found.*")
    public void testDeleteGroup() throws IdentityStoreException, GroupNotFoundException {

        initConnector();
        privilegedIdentityStoreConnector.deleteGroup("engineering");
        privilegedIdentityStoreConnector.getGroupBuilder("groupname", "engineering");
    }
}
