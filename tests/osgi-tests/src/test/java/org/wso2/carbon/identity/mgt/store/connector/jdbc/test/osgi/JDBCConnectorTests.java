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

package org.wso2.carbon.identity.mgt.store.connector.jdbc.test.osgi;

import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.testng.annotations.Listeners;
import org.wso2.carbon.identity.mgt.RealmService;
import org.wso2.carbon.osgi.test.util.CarbonSysPropConfiguration;
import org.wso2.carbon.osgi.test.util.OSGiTestConfigurationUtils;
//import org.wso2.carbon.security.caas.user.core.bean.Action;
//import org.wso2.carbon.security.caas.user.core.bean.Permission;
//import org.wso2.carbon.security.caas.user.core.bean.Resource;

import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;

/**
 * Carbon Security JDBC connector OSGi tests.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class JDBCConnectorTests {

    public static final String DEFAULT_USERNAME = "admin";
    public static final String DEFAULT_ROLE = "admin";
    public static final String DEFAULT_GROUP = "is";
    public static final String DEFAULT_USER_ID = "41dadd2aea6e11e59ce95e5517507c66";
    public static final String DEFAULT_ROLE_ID = "985b79ecfcdf11e586aa5e5517507c66";
    public static final String DEFAULT_GROUP_ID = "a422aa98ecf411e59ce95e5517507c66";
    public static final String DEFAULT_PERMISSION_ID = "f61a1c240df011e6a1483e1d05defe78";
    public static final String DEFAULT_NAMESPACE = "reg";
    public static final String DEFAULT_AUTHORIZATION_STORE = "JDBCAuthorizationStore";
    public static final String DEFAULT_RESOURCE_PATH = "root/resource/id";
//    public static final Resource DEFAULT_RESOURCE = new Resource(DEFAULT_NAMESPACE, DEFAULT_RESOURCE_PATH,
//            "41dadd2aea6e11e59ce95e5517507c66");
//    public static final Action ACTION_ADD = new Action(DEFAULT_NAMESPACE, "add");
//    public static final Permission DEFAULT_PERMISSION = new Permission(DEFAULT_RESOURCE, ACTION_ADD);

    @Inject
    protected RealmService realmService;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = new ArrayList<>();

        optionList.add(mavenBundle()
                .groupId("org.ops4j.pax.logging")
                .artifactId("pax-logging-log4j2")
                .versionAsInProject());
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
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.caching")
                .artifactId("org.wso2.carbon.caching")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.security.userstore")
                .artifactId("org.wso2.carbon.identity.mgt.store.connector.jdbc")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.security.userstore")
                .artifactId("org.wso2.carbon.security.store.connector.jdbc")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.security.caas")
                .artifactId("org.wso2.carbon.security.caas")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("org.wso2.carbon.identity.mgt")
                .artifactId("org.wso2.carbon.identity.mgt")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("commons-io.wso2")
                .artifactId("commons-io")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("com.zaxxer")
                .artifactId("HikariCP")
                .versionAsInProject());
        optionList.add(mavenBundle()
                .groupId("com.h2database")
                .artifactId("h2")
                .versionAsInProject());

        CarbonSysPropConfiguration sysPropConfiguration = new CarbonSysPropConfiguration();
        sysPropConfiguration.setCarbonHome(System.getProperty("carbon.home"));
        sysPropConfiguration.setServerKey("carbon-security");
        sysPropConfiguration.setServerName("WSO2 Carbon Security Server");
        sysPropConfiguration.setServerVersion("1.0.0");

        optionList = OSGiTestConfigurationUtils.getConfiguration(optionList, sysPropConfiguration);

        return optionList.toArray(new Option[optionList.size()]);
    }
}
