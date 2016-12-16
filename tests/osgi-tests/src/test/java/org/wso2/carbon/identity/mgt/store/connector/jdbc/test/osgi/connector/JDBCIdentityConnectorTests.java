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
import org.wso2.carbon.identity.mgt.connector.Attribute;
import org.wso2.carbon.identity.mgt.connector.IdentityStoreConnector;
import org.wso2.carbon.identity.mgt.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.identity.mgt.connector.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreConnectorException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.connector.factory.JDBCIdentityStoreConnectorFactory;
import org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi.JDBCConnectorTests;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;

public class JDBCIdentityConnectorTests extends JDBCConnectorTests {

    @Inject
    @Filter("(connector-type=JDBCIdentityStore)")
    protected IdentityStoreConnectorFactory identityStoreConnectorFactory;

    private static IdentityStoreConnector identityStoreConnector;

    private static String connectorUserId;
    private static String connectorGroupId;

    private void initConnector() throws IdentityStoreConnectorException {
        Assert.assertNotNull(identityStoreConnectorFactory);
        Assert.assertTrue(identityStoreConnectorFactory instanceof JDBCIdentityStoreConnectorFactory);
        identityStoreConnector = (IdentityStoreConnector)
                identityStoreConnectorFactory.getInstance();
        IdentityStoreConnectorConfig identityStoreConnectorConfig = new IdentityStoreConnectorConfig();
        identityStoreConnectorConfig.setConnectorId("JDBCIS1");
        identityStoreConnectorConfig.setConnectorType("JDBCPrivilegedIdentityStore");
        Map<String, String> properties = new HashMap<>();
        properties.put("dataSource", "WSO2_CARBON_DB");
        properties.put("databaseType", "MySQL");
        identityStoreConnectorConfig.setProperties(properties);
        identityStoreConnector.init(identityStoreConnectorConfig);
    }

    @Test(priority = 2)
    public void testAddUserConnector() throws IdentityStoreConnectorException {

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
        attribute3.setAttributeName("firstName");
        attribute3.setAttributeValue("Maduranga");
        attributes.add(attribute3);
        Attribute attribute4 = new Attribute();
        attribute4.setAttributeName("lastName");
        attribute4.setAttributeValue("Siriwardena");
        attributes.add(attribute4);

        connectorUserId = identityStoreConnector.addUser(attributes);

        List<Attribute> attributesRetrieved = identityStoreConnector.getUserAttributeValues(connectorUserId);
        Assert.assertNotNull(attributesRetrieved);
        Assert.assertTrue(attributesRetrieved.size() == 4);
        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributeMap.get("username"), "maduranga");
        Assert.assertEquals(attributeMap.get("email"), "maduranga@wso2.com");
        Assert.assertEquals(attributeMap.get("firstName"), "Maduranga");
        Assert.assertEquals(attributeMap.get("lastName"), "Siriwardena");
    }

    @Test(priority = 3)
    public void testAddGroupConnector() throws IdentityStoreConnectorException {

        List<Attribute> attributes = new ArrayList<>();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("groupName");
        attribute1.setAttributeValue("engineering");
        attributes.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("reportsto");
        attribute2.setAttributeValue("director@wso2.com");
        attributes.add(attribute2);

        connectorGroupId = identityStoreConnector.addGroup(attributes);

        List<Attribute> attributeRetrieved = identityStoreConnector.getGroupAttributeValues(connectorGroupId);
        Assert.assertNotNull(attributeRetrieved);
        Assert.assertEquals(attributeRetrieved.size(), 2);
    }

    @Test(priority = 8)
    public void testUpdateUserAttributesPutConnector() throws IdentityStoreConnectorException {

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
        attribute3.setAttributeName("firstName");
        attribute3.setAttributeValue("Maduranga1");
        attributesToUpdate.add(attribute3);

        identityStoreConnector.updateUserAttributes(connectorUserId, attributesToUpdate);

        List<Attribute> attributesRetrieved = identityStoreConnector.getUserAttributeValues(connectorUserId);

        Assert.assertEquals(attributesRetrieved.size(), 3);

        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributeMap.get("username"), "maduranga1");
        Assert.assertEquals(attributeMap.get("email"), "maduranga1@wso2.com");
        Assert.assertEquals(attributeMap.get("firstName"), "Maduranga1");
    }

    @Test(priority = 9)
    public void testUpdateUserAttributesPatchConnector() throws IdentityStoreConnectorException {

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
        attribute3.setAttributeName("lastName");
        attribute3.setAttributeValue("Siriwardena1");
        attributesToUpdate.add(attribute3);

        List<Attribute> attributesToDelete = new ArrayList();
        Attribute attribute5 = new Attribute();
        attribute5.setAttributeName("firstName");
        attribute5.setAttributeValue("Maduranga1");
        attributesToDelete.add(attribute5);

        identityStoreConnector.updateUserAttributes(connectorUserId, attributesToUpdate, attributesToDelete);

        List<Attribute> attributesRetrieved = identityStoreConnector.getUserAttributeValues(connectorUserId);

        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributesRetrieved.size(), 3);
        Assert.assertEquals(attributeMap.get("username"), "maduranga");
        Assert.assertEquals(attributeMap.get("email"), "maduranga@wso2.com");
        Assert.assertEquals(attributeMap.get("lastName"), "Siriwardena1");
    }

    @Test(priority = 10)
    public void testDeleteUserConnector() throws UserNotFoundException, IdentityStoreConnectorException {

        identityStoreConnector.deleteUser(connectorUserId);
        List<Attribute> userAttributeValues = identityStoreConnector.getUserAttributeValues(connectorUserId);

        Assert.assertEquals(userAttributeValues.size(), 0);
    }

    @Test(priority = 11)
    public void testUpdateGroupAttributesPutConnector() throws IdentityStoreConnectorException {

        List<Attribute> attributesToUpdate = new ArrayList();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("groupName");
        attribute1.setAttributeValue("engineering1");
        attributesToUpdate.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("email");
        attribute2.setAttributeValue("engineering1@wso2.com");
        attributesToUpdate.add(attribute2);
        Attribute attribute3 = new Attribute();
        attribute3.setAttributeName("reportsto");
        attribute3.setAttributeValue("director1@wso2.com");
        attributesToUpdate.add(attribute3);

        identityStoreConnector.updateGroupAttributes(connectorGroupId, attributesToUpdate);

        List<Attribute> attributesRetrieved = identityStoreConnector.getGroupAttributeValues(connectorGroupId);

        Assert.assertEquals(attributesRetrieved.size(), 3);

        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributeMap.get("groupName"), "engineering1");
        Assert.assertEquals(attributeMap.get("email"), "engineering1@wso2.com");
        Assert.assertEquals(attributeMap.get("reportsto"), "director1@wso2.com");
    }

    @Test(priority = 12)
    public void testUpdateGroupAttributesPatchConnector() throws IdentityStoreConnectorException {

        String now = LocalDateTime.now().toString();

        List<Attribute> attributesToUpdate = new ArrayList();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("groupName");
        attribute1.setAttributeValue("engineering");
        attributesToUpdate.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("email");
        attribute2.setAttributeValue("engineering@wso2.com");
        attributesToUpdate.add(attribute2);
        Attribute attribute3 = new Attribute();
        attribute3.setAttributeName("createdon");
        attribute3.setAttributeValue(now);
        attributesToUpdate.add(attribute3);

        List<Attribute> attributesToDelete = new ArrayList();
        Attribute attribute5 = new Attribute();
        attribute5.setAttributeName("reportsto");
        attribute5.setAttributeValue("director1@wso2.com");
        attributesToDelete.add(attribute5);

        identityStoreConnector.updateGroupAttributes(connectorGroupId, attributesToUpdate, attributesToDelete);

        List<Attribute> attributesRetrieved = identityStoreConnector.getGroupAttributeValues(connectorGroupId);

        Map<String, String> attributeMap = new HashMap<>();
        for (Attribute attribute : attributesRetrieved) {
            attributeMap.put(attribute.getAttributeName(), attribute.getAttributeValue());
        }
        Assert.assertEquals(attributeMap.get("groupName"), "engineering");
        Assert.assertEquals(attributeMap.get("email"), "engineering@wso2.com");
        Assert.assertEquals(attributeMap.get("createdon"), now);
    }

    @Test(priority = 13)
    public void testDeleteGroupConnector() throws IdentityStoreConnectorException, GroupNotFoundException {

        identityStoreConnector.deleteGroup(connectorGroupId);
        List<Attribute> groups = identityStoreConnector.getGroupAttributeValues(connectorGroupId);
        Assert.assertNotNull(groups);
    }

}
