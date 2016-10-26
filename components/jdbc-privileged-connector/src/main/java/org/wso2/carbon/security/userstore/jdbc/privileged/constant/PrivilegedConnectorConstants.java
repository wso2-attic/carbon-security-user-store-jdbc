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

package org.wso2.carbon.security.userstore.jdbc.privileged.constant;

/**
 * Connector related constants.
 */
public class PrivilegedConnectorConstants {


    /**
     * Placeholders related to the named prepared statement.
     */
    public static final class SQLPlaceholders {
        public static final String USER_UNIQUE_ID_UPDATE = "user_unique_id_update";
        public static final String GROUP_UNIQUE_ID_UPDATE = "group_unique_id_update";
    }

    /**
     * Query type related constants.
     */
    public static final class QueryTypes {
        public static final String SQL_QUERY_ADD_USER_ATTRIBUTES = "sql_query_add_user_attributes";
        public static final String SQL_QUERY_ADD_GROUP_ATTRIBUTES = "sql_query_add_group_attributes";
        public static final String SQL_QUERY_ADD_USER = "sql_query_add_user";
        public static final String SQL_QUERY_UPDATE_USER = "sql_query_update_user";
        public static final String SQL_QUERY_UPDATE_GROUP = "sql_query_update_group";
        public static final String SQL_QUERY_ADD_GROUP = "sql_query_add_group";
        public static final String SQL_QUERY_ADD_USER_GROUP = "sql_query_add_user_group";
        public static final String SQL_QUERY_REMOVE_ALL_GROUPS_OF_USER = "sql_query_remove_all_groups_of_user";
        public static final String SQL_QUERY_REMOVE_ALL_USERS_OF_GROUP = "sql_query_remove_all_users_of_group";
        public static final String SQL_QUERY_REMOVE_GROUP_OF_USER = "sql_query_remove_group_of_user";
        public static final String SQL_QUERY_REMOVE_ALL_ATTRIBUTES_OF_USER = "sql_query_remove_all_attributes_of_user";
        public static final String SQL_QUERY_REMOVE_ALL_ATTRIBUTES_OF_GROUP =
                "sql_query_remove_all_attributes_of_group";
        public static final String SQL_QUERY_REMOVE_ATTRIBUTE_OF_USER = "sql_query_remove_attribute_of_user";
        public static final String SQL_QUERY_REMOVE_ATTRIBUTE_OF_GROUP = "sql_query_remove_attribute_of_group";
        public static final String SQL_QUERY_DELETE_USER = "sql_query_delete_user";
        public static final String SQL_QUERY_DELETE_GROUP = "sql_query_delete_group";
        public static final String SQL_QUERY_UPDATE_USER_ATTRIBUTES = "sql_query_update_user_claims";
        public static final String SQL_QUERY_UPDATE_GROUP_ATTRIBUTES = "sql_query_update_group_claims";
    }
}
