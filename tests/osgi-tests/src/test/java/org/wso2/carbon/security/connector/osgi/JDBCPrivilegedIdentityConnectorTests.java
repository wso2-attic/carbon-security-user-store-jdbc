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

package org.wso2.carbon.security.connector.osgi;

import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.util.Filter;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.user.mgt.store.connector.PrivilegedIdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.privileged.connector.factory.JDBCPrivilegedIdentityStoreConnectorFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.inject.Inject;

@ExamReactorStrategy(PerClass.class)
public class JDBCPrivilegedIdentityConnectorTests extends JDBCPrivilegedConnectorTests {

    @Inject
    @Filter("(connector-type=JDBCPrivilegedIdentityStore)")
    protected IdentityStoreConnectorFactory identityStoreConnectorFactory;

    private PrivilegedIdentityStoreConnector privilegedIdentityStoreConnector;

    public JDBCPrivilegedIdentityConnectorTests() throws Exception {
    }

    private void initConnector() throws IdentityStoreException {
        Assert.assertNotNull(identityStoreConnectorFactory);
        Assert.assertTrue(identityStoreConnectorFactory instanceof JDBCPrivilegedIdentityStoreConnectorFactory);
        privilegedIdentityStoreConnector = (PrivilegedIdentityStoreConnector)
                identityStoreConnectorFactory.getConnector();
        IdentityStoreConnectorConfig identityStoreConnectorConfig = new IdentityStoreConnectorConfig();
        identityStoreConnectorConfig.setConnectorName("JDBCISC1");
        identityStoreConnectorConfig.setConnectorType("JDBCPrivilegedIdentityStore");
        identityStoreConnectorConfig.setDomainName("A");
        identityStoreConnectorConfig.setPrimaryAttributeName("username");
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
        identityStoreConnectorConfig.setProperties(properties);
        privilegedIdentityStoreConnector.init("JDBCISC1", identityStoreConnectorConfig);
    }

    @Test(priority = 2)
    public void testAddUser() throws IdentityStoreException {
        //TODO check how to initialize privilegedIdentityStoreConnector before tests
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

        List<Attribute> attributeRetrieved = privilegedIdentityStoreConnector.getUserAttributeValues("maduranga");
        Assert.assertNotNull(attributeRetrieved);
        Assert.assertTrue(attributeRetrieved.size() > 0);
        Assert.assertTrue(attributeRetrieved.size() == 3);
    }

    @Test(priority = 3)
    public void testAddGroup() throws IdentityStoreException {
        //TODO check how to initialize privilegedIdentityStoreConnector before tests
        initConnector();

        List<Attribute> attributes = new ArrayList<>();
        Attribute attribute1 = new Attribute();
        attribute1.setAttributeName("username");
        attribute1.setAttributeValue("engineering");
        attributes.add(attribute1);
        Attribute attribute2 = new Attribute();
        attribute2.setAttributeName("reportsto");
        attribute2.setAttributeValue("director@wso2.com");
        attributes.add(attribute2);

        privilegedIdentityStoreConnector.addGroup(attributes);

        List<Attribute> attributeRetrieved = privilegedIdentityStoreConnector.getGroupAttributeValues("engineering");
        Assert.assertNotNull(attributeRetrieved);
        Assert.assertTrue(attributeRetrieved.size() > 0);
        Assert.assertEquals(attributeRetrieved.size(), 1);
    }

    @Test(priority = 4)
    public void testGroupsOfUser() throws IdentityStoreException {
        //TODO check how to initialize privilegedIdentityStoreConnector before tests
        initConnector();

        List<String> groups = new ArrayList();
        groups.add("engineering");

        privilegedIdentityStoreConnector.updateGroupsOfUser("maduranga", groups);

        List<Group.GroupBuilder> groupBuilders = privilegedIdentityStoreConnector.getGroupBuildersOfUser("maduranga");
        List<Group> groupListOfUser = new ArrayList<>();
        for (Group.GroupBuilder groupBuilder : groupBuilders){
            groupBuilder.setDomain(defaultDomain);
            groupBuilder.setIdentityStore(privilegedRealmService.getIdentityStore());
            groupBuilder.setAuthorizationStore(privilegedRealmService.getAuthorizationStore());
            //TODO need to remove tenant domain from group object
            groupBuilder.setTenantDomain("TENANT");
            groupListOfUser.add(groupBuilder.build());
        }

        Assert.assertEquals(groupBuilders.size(), 1);
        //TODO need to check the correct group is assigned
    }


}
