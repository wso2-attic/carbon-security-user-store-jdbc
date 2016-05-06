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

package org.wso2.carbon.security.userstore.jdbc.queries;

import org.wso2.carbon.security.userstore.jdbc.constant.ConnectorConstants;

/**
 * SQL queries for MySQL family based databases.
 * @since 1.0.0
 */
public class MySQLFamilySQLQueryFactory extends SQLQueryFactory {

    private static final String COMPARE_PASSWORD_HASH =
            "SELECT UM_USER.USER_UNIQUE_ID, UM_USER.IDENTITY_STORE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_USER LEFT JOIN UM_TENANT " +
            "ON UM_USER.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_USER.USERNAME = :username; AND UM_USER.PASSWORD = :hashed_password;";

    private static final String GET_USER_FROM_USERNAME =
            "SELECT UM_USER.USER_UNIQUE_ID, UM_USER.CREDENTIAL_STORE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_USER LEFT JOIN UM_TENANT " +
            "ON UM_USER.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_USER.USERNAME = :username;";

    private static final String GET_USER_FROM_ID =
            "SELECT UM_USER.USERNAME, UM_USER.CREDENTIAL_STORE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_USER LEFT JOIN UM_TENANT " +
            "ON UM_USER.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_USER.USER_UNIQUE_ID = :user_id;";

    private static final String GET_GROUP_FROM_NAME =
            "SELECT UM_GROUP.GROUP_UNIQUE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_GROUP LEFT JOIN UM_TENANT " +
            "ON UM_GROUP.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_GROUP.GROUP_NAME = :groupname;";

    private static final String GET_GROUP_FROM_ID =
            "SELECT UM_GROUP.GROUP_NAME, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_GROUP LEFT JOIN UM_TENANT " +
            "ON UM_GROUP.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_GROUP.GROUP_UNIQUE_ID = :group_id;";

    private static final String GET_USER_ATTRIBUTES =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_USER_ATTRIBUTES " +
            "WHERE USER_ID = (SELECT USER_ID " +
                             "FROM UM_USER " +
                             "WHERE USER_UNIQUE_ID = :user_id;)";

    private static final String DELETE_USER =
            "DELETE FROM UM_USER " +
            "WHERE USER_UNIQUE_ID = :userId;";

    private static final String DELETE_GROUP =
            "DELETE FROM UM_GROUP " +
            "WHERE GROUP_UNIQUE_ID = :groupId;";

    private static final String GET_GROUP_IDS =
            "SELECT ID " +
            "FROM UM_GROUP " +
            "WHERE GROUP_NAME IN (:groupnames;)";

    private static final String ADD_USER =
            "INSERT INTO UM_USER (USER_UNIQUE_ID, USERNAME, PASSWORD) " +
            "VALUES (:user_unique_id;, :username;, :password;)";

    private static final String ADD_USER_ATTRIBUTES =
            "INSERT INTO UM_USER_ATTRIBUTES (ATTR_NAME, ATTR_VALUE, USER_ID) " +
            "VALUES (:attr_name;, :attr_val;, :user_id;)";

    private static final String ADD_USER_GROUPS =
            "INSERT INTO UM_USER_GROUP (USER_ID, GROUP_ID) " +
            "VALUES (:user_id;, :group_id;)";

    private static final String GET_USER_IDS =
            "SELECT ID " +
            "FROM UM_USER " +
            "WHERE USERNAME IN (:usernames;)";

    private static final String ADD_GROUP =
            "INSERT INTO (GROUP_NAME, GROUP_UNIQUE_ID) " +
            "VALUES (:group_name;, :group_id;)";

    private static final String LIST_USERS =
            "SELECT UM_USER.USERNAME, UM_USER.USER_UNIQUE_ID, UM_USER.CREDENTIAL_STORE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_USER LEFT JOIN UM_TENANT " +
            "ON UM_USER.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_USER.USERNAME LIKE :username; " +
            "LIMIT :length; " +
            "OFFSET :offset;";

    private static final String GET_GROUPS_OF_USER =
            "SELECT UM_GROUP.GROUP_NAME, UM_GROUP.GROUP_UNIQUE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_GROUP LEFT JOIN UM_TENANT " +
            "ON UM_GROUP.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_GROUP.ID IN (SELECT GROUP_ID " +
                        "FROM UM_USER_GROUP " +
                        "WHERE USER_ID = (SELECT ID " +
                                         "FROM UM_USER " +
                                         "WHERE USER_UNIQUE_ID = :user_id;))";

    private static final String GET_USERS_OF_GROUP =
            "SELECT UM_USER.USERNAME, UM_USER.USER_UNIQUE_ID, UM_USER.CREDENTIAL_STORE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_USER LEFT JOIN UM_TENANT " +
            "ON UM_USER.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_USER.ID IN (SELECT USER_ID " +
                        "FROM UM_USER_GROUP " +
                        "WHERE GROUP_ID = (SELECT ID " +
                                          "FROM UM_GROUP " +
                                          "WHERE GROUP_UNIQUE_ID = :group_id;))";

    private static final String GET_PASSWORD_INFO =
            "SELECT PASSWORD_SALT, HASH_ALGO " +
            "FROM UM_PASSWORD_INFO " +
            "WHERE USER_ID = (SELECT ID " +
                             "FROM UM_USER " +
                             "WHERE USERNAME = :username;)";

    private static final String ADD_PASSWORD_INFO =
            "INSERT INTO UM_PASSWORD_INFO (USER_ID, PASSWORD_SALT, HASH_ALGO) " +
            "VALUES (:user_id;, :password_salt;, :hash_algo;)";

    private static final String SET_USER_ATTRIBUTE =
            "INSERT INTO UM_USER_ATTRIBUTES (ATTR_NAME, ATTR_VALUE, USER_ID) " +
            "VALUES (:attr_name;, :attr_val;, (SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_id;))";

    private static final String DELETE_USER_ATTRIBUTE =
            "DELETE FROM UM_USER_ATTRIBUTES " +
            "WHERE USER_ID = (SELECT ID " +
                             "FROM UM_USER " +
                             "WHERE USER_UNIQUE_ID = :user_id;) " +
            "AND ATTR_NAME = :attr_name;";

    private static final String GET_USER_ATTRIBUTES_FROM_NAME =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_USER_ATTRIBUTES " +
            "WHERE USER_ID = (SELECT ID " +
                             "FROM UM_USER " +
                             "WHERE USER_UNIQUE_ID = :user_id;) " +
                             "AND ATTR_NAME IN (:attr_names;)";

    private static final String UPDATE_CREDENTIALS =
            "UPDATE UM_USER " +
            "SET PASSWORD = :credential; " +
            "WHERE USERNAME = :username;";

    private static final String REMOVE_GROUP_FROM_USER =
            "DELETE FROM UM_USER_GROUP " +
            "WHERE USER_ID = :user_id; AND GROUP_ID = :group_id;";

    private static final String RENAME_USER =
            "UPDATE UM_USER " +
            "SET USERNAME = :new_name; " +
            "WHERE USER_UNIQUE_ID = :user_id;";

    private static final String IS_USER_IN_GROUP =
            "SELECT ID " +
            "FROM UM_USER_GROUP " +
            "WHERE USER_ID = (SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_id;) " +
            "AND GROUP_ID = (SELECT ID FROM UM_GROUP WHERE GROUP_UNIQUE_ID = :group_id;)";

    private static final String GET_ROLE =
            "SELECT ROLE_UNIQUE_ID " +
            "FROM UM_ROLE WHERE ROLE_NAME = :role_name;";

    private static final String GET_ROLES_FOR_USER =
            "SELECT ROLE_NAME, ROLE_UNIQUE_ID " +
            "FROM UM_ROLE " +
            "WHERE ID IN (SELECT ROLE_ID " +
                        "FROM UM_USER_ROLE " +
                        "WHERE USER_UNIQUE_ID = :user_id;)";

    private static final String GET_PERMISSIONS_FOR_ROLE =
            "SELECT RESOURCE_ID, ACTION, PERMISSION_UNIQUE_ID " +
            "FROM UM_PERMISSION " +
            "WHERE ID IN (SELECT PERMISSION_ID " +
                        "FROM UM_ROLE_PERMISSION " +
                        "WHERE ROLE_ID = (SELECT ID " +
                                         "FROM UM_ROLE " +
                                         "WHERE ROLE_UNIQUE_ID = :role_id;))";

    private static final String GET_ROLES_FOR_GROUP =
            "SELECT ROLE_NAME, ROLE_UNIQUE_ID " +
            "FROM UM_ROLE " +
            "WHERE ID IN (SELECT ROLE_ID " +
                        "FROM UM_GROUP_ROLE " +
                        "WHERE GROUP_UNIQUE_ID = :group_id;)";

    private static final String LIST_GROUP =
            "SELECT UM_GROUP.GROUP_NAME, UM_GROUP.GROUP_UNIQUE_ID, UM_TENANT.DOMAIN_NAME " +
            "FROM UM_GROUP LEFT JOIN UM_TENANT " +
            "ON UM_GROUP.TENANT_ID = UM_TENANT.ID " +
            "WHERE UM_GROUP.GROUP_NAME LIKE :group_name; " +
            "LIMIT :length; " +
            "OFFSET :offset;";

    private static final String ADD_PERMISSION =
            "INSERT INTO UM_PERMISSION (RESOURCE_ID, ACTION, PERMISSION_UNIQUE_ID) " +
            "VALUES (:resource_id;, :action;, :permission_id;)";

    private static final String GET_PERMISSION_IDS =
            "SELECT ID " +
            "FROM UM_PERMISSION " +
            "WHERE RESOURCE_ID IN (:resource_ids;) AND ACTION IN (:actions;)";

    private static final String ADD_ROLE =
            "INSERT INTO UM_ROLE (ROLE_NAME, ROLE_UNIQUE_ID) " +
            "VALUES (:role_name;, :role_unique_id;)";

    private static final String ADD_ROLE_PERMISSION =
            "INSERT INTO UM_ROLE_PERMISSION (ROLE_ID, PERMISSION_ID)" +
            "VALUES (:role_id;, :permission_id;)";

    private static final String GET_USERS_OF_ROLE =
            "SELECT USER_UNIQUE_ID, IDENTITY_STORE_ID " +
            "FROM UM_USER_ROLE " +
            "WHERE ROLE_ID = (SELECT ID " +
                             "FROM UM_ROLE " +
                             "WHERE ROLE_UNIQUE_ID = :role_id;)";

    private static final String GET_GROUPS_OF_ROLE =
            "SELECT GROUP_UNIQUE_ID, IDENTITY_STORE_ID " +
            "FROM UM_GROUP_ROLE " +
            "WHERE ROLE_ID = (SELECT ID " +
                             "FROM UM_ROLE " +
                             "WHERE ROLE_UNIQUE_ID = :role_id;)";

    private static final String DELETE_ROLE =
            "DELETE FROM UM_ROLE " +
            "WHERE ROLE_UNIQUE_ID = :role_id;";

    private static final String DELETE_PERMISSION =
            "DELETE FROM UM_PERMISSION " +
            "WHERE PERMISSION_UNIQUE_ID = :permission_id;";

    private static final String IS_USER_IN_ROLE =
            "SELECT ID " +
            "FROM UM_USER_ROLE " +
            "WHERE USER_UNIQUE_ID = :user_id; " +
            "AND IDENTITY_STORE_ID = :identity_store_id; " +
            "AND ROLE_ID = (SELECT ID " +
                           "FROM UM_ROLE " +
                           "WHERE ROLE_NAME = :role_name;)";

    private static final String IS_GROUP_IN_ROLE =
            "SELECT ID " +
            "FROM UM_GROUP_ROLE " +
            "WHERE GROUP_UNIQUE_ID = :group_id; " +
            "AND IDENTITY_STORE_ID = :identity_store_id; " +
            "AND ROLE_ID = (SELECT ID " +
                           "FROM UM_ROLE " +
                           "WHERE ROLE_NAME = :role_name;)";

    private static final String DELETE_ROLES_OF_USER =
            "DELETE FROM UM_USER_ROLE " +
            "WHERE USER_UNIQUE_ID = :user_id; " +
            "AND IDENTITY_STORE_ID = :identity_store_id; ";

    private static final String ADD_ROLES_TO_USER =
            "INSERT INTO UM_USER_ROLE(USER_UNIQUE_ID, IDENTITY_STORE_ID, ROLE_ID) " +
            "VALUES (:user_id;, :identity_store_id;, (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;))";

    private static final String ADD_ROLES_TO_GROUP =
            "INSERT INTO UM_GROUP_ROLE(GROUP_UNIQUE_ID, IDENTITY_STORE_ID, ROLE_ID) " +
            "VALUES (:group_id;, :identity_store_id;, (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;))";

    private static final String DELETE_ROLES_FROM_GROUP =
            "DELETE FROM UM_GROUP_ROLE WHERE GROUP_UNIQUE_ID = :group_id; AND :identity_store_id;";

    private static final String DELETE_GROUPS_FROM_ROLE =
            "DELETE FROM UM_GROUP_ROLE WHERE ROLE_ID = :role_id;";

    private static final String DELETE_USERS_OF_ROLE =
            "DELETE FROM UM_USER_ROLE WHERE ROLE_ID = :role_id;";

    private static final String DELETE_PERMISSIONS_FROM_ROLE =
            "DELETE FROM UM_ROLE_PERMISSION WHERE ROLE_ID = :role_id;";

    private static final String DELETE_GIVEN_ROLES_FROM_USER =
            "DELETE FROM UM_USER_ROLE " +
            "WHERE USER_UNIQUE_ID = :user_id; " +
            "AND IDENTITY_STORE_ID = :identity_store_id; " +
            "AND ROLE_ID = (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_Id;)";

    private static final String DELETE_GIVEN_ROLES_FROM_GROUP =
            "DELETE FROM UM_GROUP_ROLE " +
            "WHERE USER_UNIQUE_ID = :user_id; " +
            "AND IDENTITY_STORE_ID = :identity_store_id; " +
            "AND ROLE_ID = (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;)";

    private static final String DELETE_GIVEN_PERMISSIONS_FROM_ROLE =
            "DELETE FROM UM_ROLE_PERMISSION " +
            "WHERE ROLE_ID = (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;) " +
            "AND PERMISSION_ID = (SELECT ID FROM UM_PERMISSION WHERE PERMISSION_UNIQUE_ID = :permission_id;)";

    public MySQLFamilySQLQueryFactory() {

        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COMPARE_PASSWORD_HASH, COMPARE_PASSWORD_HASH);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_USERNAME, GET_USER_FROM_USERNAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ID, GET_USER_FROM_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_NAME, GET_GROUP_FROM_NAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ID, GET_GROUP_FROM_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES, GET_USER_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER, DELETE_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP, DELETE_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_IDS, GET_GROUP_IDS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER, ADD_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_CLAIMS, ADD_USER_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUPS, ADD_USER_GROUPS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_IDS, GET_USER_IDS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_GROUP, ADD_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS, LIST_USERS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUPS_OF_USER, GET_GROUPS_OF_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USERS_OF_GROUP, GET_USERS_OF_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PASSWORD_INFO, GET_PASSWORD_INFO);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PASSWORD_INFO, ADD_PASSWORD_INFO);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_SET_USER_ATTRIBUTE, SET_USER_ATTRIBUTE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER_ATTRIBUTE, DELETE_USER_ATTRIBUTE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES_FROM_NAME,
                GET_USER_ATTRIBUTES_FROM_NAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_UPDATE_CREDENTIAL, UPDATE_CREDENTIALS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_REMOVE_GROUP_FROM_USER, REMOVE_GROUP_FROM_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_RENAME_USER, RENAME_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_IS_USER_IN_GROUP, IS_USER_IN_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLE, GET_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_USER, GET_ROLES_FOR_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSIONS_FOR_ROLE, GET_PERMISSIONS_FOR_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_GROUP, GET_ROLES_FOR_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_GROUP, LIST_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSION, ADD_PERMISSION);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSION_IDS, GET_PERMISSION_IDS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLE, ADD_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE, ADD_ROLE_PERMISSION);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USERS_OF_ROLE, GET_USERS_OF_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUPS_OF_ROLE, GET_GROUPS_OF_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_ROLE, DELETE_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_PERMISSION, DELETE_PERMISSION);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_IS_USER_IN_ROLE, IS_USER_IN_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_IS_GROUP_IN_ROLE, IS_GROUP_IN_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_ROLES_FROM_USER, DELETE_ROLES_OF_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_USER, ADD_ROLES_TO_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLES_TO_GROUP, ADD_ROLES_TO_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_ROLES_FROM_GROUP, DELETE_ROLES_FROM_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUPS_FROM_ROLE, DELETE_GROUPS_FROM_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USERS_FROM_ROLE, DELETE_USERS_OF_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_PERMISSIONS_FROM_ROLE,
                DELETE_PERMISSIONS_FROM_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_ROLES_FROM_USER,
                DELETE_GIVEN_ROLES_FROM_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_ROLES_FROM_GROUP,
                DELETE_GIVEN_ROLES_FROM_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GIVEN_PERMISSIONS_FROM_ROLE,
                DELETE_GIVEN_PERMISSIONS_FROM_ROLE);
    }
}
