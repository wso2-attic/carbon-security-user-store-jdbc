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

package org.wso2.carbon.security.userstore.jdbc.util;

import org.wso2.carbon.datasource.core.api.DataSourceService;
import org.wso2.carbon.datasource.core.exception.DataSourceException;
import org.wso2.carbon.security.caas.user.core.util.PasswordHandler;

import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;

/**
 * Database related utility methods.
 */
public class DatabaseUtil {

    private static final DatabaseUtil instance = new DatabaseUtil();

    private DataSourceService dataSourceService;
    private Map<String, PasswordHandler> passwordHandlerList = new HashMap<>();

    private DatabaseUtil() {
        super();
    }

    public static DatabaseUtil getInstance() {
        return instance;
    }

    public PasswordHandler getPasswordHandler(String handlerName) {
        return passwordHandlerList.get(handlerName);
    }

    public DataSource getDataSource(String dataSourceName) throws DataSourceException {

        if (dataSourceService == null) {
            throw new RuntimeException("Datasource service is null. Cannot retrieve data source");
        }
        return (DataSource) dataSourceService.getDataSource(dataSourceName);
    }

    public void setDataSourceService(DataSourceService dataSourceService) {
        this.dataSourceService = dataSourceService;
    }

    public void setPasswordHandler(String name, PasswordHandler passwordHandler) {
        passwordHandlerList.put(name, passwordHandler);
    }
}
