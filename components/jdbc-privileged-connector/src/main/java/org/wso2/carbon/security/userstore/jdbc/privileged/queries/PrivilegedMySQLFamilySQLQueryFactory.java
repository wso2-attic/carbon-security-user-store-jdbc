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

package org.wso2.carbon.security.userstore.jdbc.privileged.queries;

import org.wso2.carbon.security.userstore.jdbc.privileged.constant.PrivilegedConnectorConstants;
import org.wso2.carbon.security.userstore.jdbc.queries.MySQLFamilySQLQueryFactory;

/**
 * SQL queries for MySQL family based databases.
 *
 * @since 1.0.0
 */
public class PrivilegedMySQLFamilySQLQueryFactory extends MySQLFamilySQLQueryFactory {

    private static final String ADD_USER_ATTRIBUTES =
            "INSERT INTO UM_USER_ATTRIBUTES (ATTR_ID, ATTR_VALUE, USER_ID) " +
                    "VALUES ((SELECT ID FROM UM_ATTRIBUTES WHERE ATTR_NAME = :attr_name;), :attr_value;, " +
                    "(SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_unique_id;)) ";

    private static final String ADD_USER =
            "INSERT INTO UM_USER (USER_UNIQUE_ID) " +
                    "VALUES (:user_unique_id;)";

    private static final String ADD_GROUP_ATTRIBUTES =
            "INSERT INTO UM_GROUP_ATTRIBUTES (ATTR_ID, ATTR_VALUE, GROUP_ID) " +
                    "VALUES ((SELECT ID FROM UM_ATTRIBUTES WHERE ATTR_NAME = :attr_name;), :attr_value;, " +
                    "(SELECT ID FROM UM_GROUP WHERE GROUP_UNIQUE_ID = :group_unique_id;)) ";

    private static final String ADD_GROUP =
            "INSERT INTO UM_GROUP (GROUP_UNIQUE_ID) " +
                    "VALUES (:group_unique_id;)";

    //TODO check whether this is possible in mysql
    private static final String UPDATE_USER = "UPDATE UM_USER USER_TEMP SET USER_UNIQUE_ID = :user_unique_id_update; " +
            "WHERE USER_TEMP.USER_UNIQUE_ID = :user_unique_id;";

    private static final String ADD_USER_GROUPS =
            "INSERT INTO UM_USER_GROUP (USER_ID, GROUP_ID) " +
                    "VALUES ((SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_unique_id;), " +
                    "(SELECT ID FROM UM_GROUP WHERE GROUP_UNIQUE_ID = :group_unique_id;))";

    private static final String REMOVE_ALL_GROUPS_OF_USER = "DELETE FROM UM_USER_GROUP " +
            "WHERE USER_ID = (SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_unique_id;)";

    private static final String REMOVE_ALL_USERS_OF_GROUP = "DELETE FROM UM_USER_GROUP " +
            "WHERE GROUP_ID = (SELECT ID FROM UM_GROUP WHERE GROUP_UNIQUE_ID = :group_unique_id;)";

    private static final String REMOVE_GROUP_OF_USER = "DELETE FROM UM_USER_GROUP " +
            "WHERE USER_ID = (SELECT ID FROM UM_GROUP WHERE GROUP_UNIQUE_ID = :group_unique_id;) " +
            "AND GROUP_ID = (SELECT ID FROM UM_GROUP WHERE GROUP_UNIQUE_ID = :group_unique_id;)";

    private static final String REMOVE_ALL_ATTRIBUTES_OF_USER = "DELETE FROM UM_USER_ATTRIBUTES " +
            "WHERE USER_ID = (SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_unique_id;)";

    private static final String REMOVE_ATTRIBUTE_OF_USER =
            "DELETE FROM UM_USER_ATTRIBUTES " +
                    "WHERE ATTR_ID = (SELECT ID FROM UM_ATTRIBUTES WHERE ATTR_NAME = :attr_name;) AND " +
                    "USER_ID = (SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_unique_id;)) ";

    private static final String DELETE_USER =
            "DELETE FROM UM_USER " +
                    "WHERE USER_UNIQUE_ID = :user_unique_id;";

    private static final String DELETE_GROUP =
            "DELETE FROM UM_GROUP " +
                    "WHERE GROUP_UNIQUE_ID = :group_unique_id;";

    public PrivilegedMySQLFamilySQLQueryFactory() {
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_ATTRIBUTES, ADD_USER_ATTRIBUTES);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER, ADD_USER);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_USER, UPDATE_USER);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP_CLAIMS, ADD_GROUP_ATTRIBUTES);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP, ADD_GROUP);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUP, ADD_USER_GROUPS);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_ALL_GROUPS_OF_USER,
                REMOVE_ALL_GROUPS_OF_USER);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_ALL_USERS_OF_GROUP,
                REMOVE_ALL_USERS_OF_GROUP);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_GROUP_OF_USER, REMOVE_GROUP_OF_USER);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_ALL_ATTRIBUTES_OF_USER,
                REMOVE_ALL_ATTRIBUTES_OF_USER);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_ATTRIBUTE_OF_USER,
                REMOVE_ATTRIBUTE_OF_USER);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER, DELETE_USER);
        sqlQueries.put(PrivilegedConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP, DELETE_GROUP);
    }
}
