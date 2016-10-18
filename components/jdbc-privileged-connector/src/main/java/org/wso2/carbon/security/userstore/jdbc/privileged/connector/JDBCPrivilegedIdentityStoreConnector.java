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

package org.wso2.carbon.security.userstore.jdbc.privileged.connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.user.mgt.store.connector.PrivilegedIdentityStoreConnector;
import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.userstore.jdbc.connector.JDBCIdentityStoreConnector;

import java.util.List;
import javax.sql.DataSource;

/**
 * Identity store connector for JDBC based stores.
 *
 * @since 1.0.0
 */
public class JDBCPrivilegedIdentityStoreConnector extends JDBCIdentityStoreConnector implements
        PrivilegedIdentityStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCPrivilegedIdentityStoreConnector.class);

    private DataSource dataSource;
    private IdentityStoreConnectorConfig identityStoreConfig;
    private String identityStoreId;


    @Override
    public void addUser(List<Attribute> list) throws IdentityStoreException {

    }

    @Override
    public void addUsers(List<List<Attribute>> list) throws IdentityStoreException {

    }

    @Override
    public void updateUserAttributes(String s, List<Attribute> list) throws IdentityStoreException {

    }

    @Override
    public void updateUserAttributes(String s, List<Attribute> list, List<Attribute> list1) throws
            IdentityStoreException {

    }

    @Override
    public void deleteUser(String s) throws IdentityStoreException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list) throws IdentityStoreException {

    }

    @Override
    public void updateGroupsOfUser(String s, List<String> list, List<String> list1) throws IdentityStoreException {

    }

    @Override
    public void addGroup(List<Attribute> list) throws IdentityStoreException {

    }

    @Override
    public void addGroups(List<List<Attribute>> list) throws IdentityStoreException {

    }

    @Override
    public void updateGroupAttributes(String s, List<Attribute> list) throws IdentityStoreException {

    }

    @Override
    public void updateGroupAttributes(String s, List<Attribute> list, List<Attribute> list1) throws
            IdentityStoreException {

    }

    @Override
    public void deleteGroup(String s) throws IdentityStoreException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list) throws IdentityStoreException {

    }

    @Override
    public void updateUsersOfGroup(String s, List<String> list, List<String> list1) throws IdentityStoreException {

    }
}
