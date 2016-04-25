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

package org.wso2.carbon.security.userstore.jdbc.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.datasource.core.api.DataSourceService;
import org.wso2.carbon.security.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.JDBCAuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.JDBCCredentialStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.JDBCIdentityStoreConnectorFactory;
import org.wso2.carbon.security.userstore.jdbc.util.DatabaseUtil;

import java.util.Dictionary;
import java.util.Hashtable;

/**
 * OSGi component for carbon security connectors.
 * @since 1.0.0
 */
@Component(
        name = "org.wso2.carbon.security.connector.jdbc.ConnectorComponent",
        immediate = true
)
public class ConnectorComponent {

    private static final Logger log = LoggerFactory.getLogger(ConnectorComponent.class);

    /**
     * Register user store connectors as OSGi services.
     * @param bundleContext @see BundleContext
     */
    @Activate
    public void registerCarbonSecurityConnectors(BundleContext bundleContext) {

        Dictionary<String, String> connectorProperties = new Hashtable<>();

        connectorProperties.put("connector-type", "JDBCIdentityStore");
        bundleContext.registerService(IdentityStoreConnectorFactory.class, new JDBCIdentityStoreConnectorFactory(),
                connectorProperties);

        connectorProperties = new Hashtable<>();
        connectorProperties.put("connector-type", "JDBCAuthorizationStore");
        bundleContext.registerService(AuthorizationStoreConnectorFactory.class,
                new JDBCAuthorizationStoreConnectorFactory(), connectorProperties);

        connectorProperties = new Hashtable<>();
        connectorProperties.put("connector-type", "JDBCCredentialStore");
        bundleContext.registerService(CredentialStoreConnectorFactory.class, new JDBCCredentialStoreConnectorFactory(),
                connectorProperties);

        if (log.isDebugEnabled()) {
            log.debug("JDBC user store connectors registered as services successfully.");
        }
    }

    @Reference(
            name = "org.wso2.carbon.datasource.DataSourceService",
            service = DataSourceService.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterDataSourceService"
    )
    protected void registerDataSourceService(DataSourceService service) {

        if (service == null) {
            log.error("Data source service is null. Registering data source service is unsuccessful.");
            return;
        }

        DatabaseUtil.getInstance().setDataSourceService(service);

        if (log.isDebugEnabled()) {
            log.debug("Data source service registered successfully.");
        }
    }

    protected void unregisterDataSourceService(DataSourceService service) {

        if (log.isDebugEnabled()) {
            log.debug("Data source service unregistered.");
        }
        DatabaseUtil.getInstance().setDataSourceService(null);
    }
}
