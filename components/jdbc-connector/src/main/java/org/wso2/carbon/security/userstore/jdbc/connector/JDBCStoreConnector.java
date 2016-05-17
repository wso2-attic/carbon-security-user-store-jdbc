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

package org.wso2.carbon.security.userstore.jdbc.connector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.userstore.jdbc.queries.MySQLFamilySQLQueryFactory;

import java.util.Map;

/**
 * Represents a JDBC based store connector.
 * @since 1.0.0
 */
public abstract class JDBCStoreConnector {

    private static Logger log = LoggerFactory.getLogger(JDBCStoreConnector.class);
    private static final boolean IS_DEBUG_ENABLED = log.isDebugEnabled();

    protected Map<String, String> sqlQueries;

    protected void loadQueries(String databaseType) {

        if (databaseType != null && (databaseType.equalsIgnoreCase("MySQL") || databaseType.equalsIgnoreCase("H2"))) {
            sqlQueries = new MySQLFamilySQLQueryFactory().getQueries();
            if (IS_DEBUG_ENABLED) {
                log.debug(String.format("%s sql queries loaded for database type: %s.", sqlQueries.size(),
                        databaseType));
            }
        } else {
            throw new StoreException("Invalid or unsupported database type specified in the configuration.");
        }
    }
}
