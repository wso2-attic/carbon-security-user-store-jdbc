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
            "SELECT USER_UNIQUE_ID " +
            "FROM UM_PASSWORD " +
            "WHERE USER_UNIQUE_ID = :user_id; " +
            "AND PASSWORD = :hashed_password;";

    private static final String GET_USER_FROM_ATTRIBUTE =
            "SELECT UM_USER.USER_UNIQUE_ID " +
            "FROM UM_USER LEFT JOIN UM_USER_ATTRIBUTES " +
            "ON UM_USER_ATTRIBUTES.USER_ID = UM_USER.ID " +
            "WHERE UM_USER_ATTRIBUTES.ATTR_ID = " +
                    "(SELECT ID " +
                    "FROM UM_ATTRIBUTES " +
                    "WHERE ATTR_NAME = :attr_name; ) " +
            "AND UM_USER_ATTRIBUTES.ATTR_VALUE = :attr_value;";

    private static final String GET_GROUP_FROM_ATTRIBUTE =
            "SELECT UM_GROUP.GROUP_UNIQUE_ID " +
            "FROM UM_GROUP LEFT JOIN UM_GROUP_ATTRIBUTES " +
            "ON UM_GROUP_ATTRIBUTES.GROUP_ID = UM_GROUP.ID " +
            "WHERE UM_GROUP_ATTRIBUTES.ATTR_ID = " +
                    "(SELECT ID " +
                    "FROM UM_ATTRIBUTES " +
                    "WHERE ATTR_NAME = :attr_name; ) " +
            "AND UM_GROUP_ATTRIBUTES.ATTR_VALUE = :attr_value;";

    private static final String GET_USER_ATTRIBUTES =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_USER_ATTRIBUTES LEFT JOIN UM_ATTRIBUTES " +
            "ON UM_USER_ATTRIBUTES.ATTR_ID = UM_ATTRIBUTES.ID" +
            "WHERE USER_ID = (SELECT USER_ID " +
                             "FROM UM_USER " +
                             "WHERE USER_UNIQUE_ID = :user_id;)";

    private static final String DELETE_USER =
            "DELETE FROM UM_USER " +
            "WHERE USER_UNIQUE_ID = :userId;";

    private static final String DELETE_GROUP =
            "DELETE FROM UM_GROUP " +
            "WHERE GROUP_UNIQUE_ID = :groupId;";

    private static final String ADD_USER =
            "INSERT INTO UM_USER (USER_UNIQUE_ID) " +
            "VALUES (:user_unique_id;)";

//    private static final String ADD_USER_ATTRIBUTES =
//            "INSERT INTO UM_USER_ATTRIBUTES (ATTR_ID, ATTR_VALUE, USER_ID) " +
//            "SELECT ID, :attr_val;, :user_id; FROM UM_ATTRIBUTES WHERE ATTR_NAME = :attr_name;";

    private static final String ADD_USER_GROUPS =
            "INSERT INTO UM_USER_GROUP (USER_ID, GROUP_ID) " +
            "VALUES (:user_id;, :group_id;)";

    private static final String LIST_USERS_BY_ATTRIBUTE =
            "SELECT UM_USER.USER_UNIQUE_ID " +
            "FROM UM_USER LEFT JOIN UM_USER_ATTRIBUTES " +
            "ON UM_USER_ATTRIBUTES.USER_ID = UM_USER.ID " +
            "WHERE UM_USER_ATTRIBUTES.ATTR_ID = " +
                    "(SELECT ID " +
                    "FROM UM_ATTRIBUTES " +
                    "WHERE ATTR_NAME = :attr_name; ) " +
            "AND UM_USER_ATTRIBUTES.ATTR_VALUE LIKE :attr_value; " +
            "LIMIT :length; " +
            "OFFSET :offset;";

    private static final String GET_GROUPS_OF_USER =
            "SELECT UM_GROUP.GROUP_UNIQUE_ID " +
            "FROM UM_GROUP " +
            "WHERE UM_GROUP.ID IN (SELECT GROUP_ID " +
                        "FROM UM_USER_GROUP " +
                        "WHERE USER_ID = (SELECT ID " +
                                         "FROM UM_USER " +
                                         "WHERE USER_UNIQUE_ID = :user_id;))";

    private static final String GET_USERS_OF_GROUP =
            "SELECT UM_USER.USER_UNIQUE_ID " +
            "FROM UM_USER " +
            "WHERE UM_USER.ID IN (SELECT USER_ID " +
                        "FROM UM_USER_GROUP " +
                        "WHERE GROUP_ID = (SELECT ID " +
                                          "FROM UM_GROUP " +
                                          "WHERE GROUP_UNIQUE_ID = :group_id;))";

    private static final String GET_PASSWORD_INFO =
            "SELECT PASSWORD_SALT, HASH_ALGO, ITERATION_COUNT, KEY_LENGTH " +
            "FROM UM_PASSWORD_INFO " +
            "WHERE USER_UNIQUE_ID = :user_id;";

    private static final String ADD_PASSWORD_INFO =
            "INSERT INTO UM_PASSWORD_INFO (USER_ID, PASSWORD_SALT, HASH_ALGO) " +
            "VALUES (:user_id;, :password_salt;, :hash_algo;)";

    private static final String SET_USER_ATTRIBUTE =
            "INSERT INTO UM_USER_ATTRIBUTES (ATTR_ID, ATTR_VALUE, USER_ID) " +
            "VALUES (" +
                    "(SELECT ID FROM UM_ATTRIBUTES WHERE ATTR_NAME = :attr_name;), " +
                    ":attr_val;, " +
                    "(SELECT ID FROM UM_USER WHERE USER_UNIQUE_ID = :user_id;))";

    private static final String DELETE_USER_ATTRIBUTE =
            "DELETE FROM UM_USER_ATTRIBUTES " +
            "WHERE USER_ID = (SELECT ID " +
                             "FROM UM_USER " +
                             "WHERE USER_UNIQUE_ID = :user_id;) " +
            "AND ATTR_ID = " +
                    "(SELECT ID " +
                    "FROM UM_ATTRIBUTES " +
                    "WHERE ATTR_NAME = :attr_name;)";

    private static final String GET_USER_ATTRIBUTES_FROM_NAME =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_USER_ATTRIBUTES LEFT JOIN UM_ATTRIBUTES " +
            "ON UM_USER_ATTRIBUTES.ATTR_ID = UM_ATTRIBUTES.ID" +
            "WHERE USER_ID = (SELECT ID " +
                             "FROM UM_USER " +
                             "WHERE USER_UNIQUE_ID = :user_id;) " +
            "AND ATTR_NAME IN (:attr_names;)";

    //TODO Need to check
    private static final String UPDATE_CREDENTIALS =
            "UPDATE UM_USER " +
            "SET PASSWORD = :credential; " +
            "WHERE USERNAME = :username;";

    private static final String REMOVE_GROUP_FROM_USER =
            "DELETE FROM UM_USER_GROUP " +
            "WHERE USER_ID = :user_id; AND GROUP_ID = :group_id;";

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

    private static final String GET_PERMISSIONS_FROM_RESOURCE_FOR_ROLE =
            "SELECT RESOURCE_NAMESPACE.NAMESPACE, UM_RESOURCE.RESOURCE_NAME, UM_RESOURCE.USER_UNIQUE_ID, " +
                    "ACTION_NAMESPACE.NAMESPACE, UM_ACTION.ACTION_NAME, UM_PERMISSION.PERMISSION_UNIQUE_ID " +
            "FROM UM_PERMISSION " +
            "LEFT JOIN UM_RESOURCE ON UM_PERMISSION.RESOURCE_ID = UM_RESOURCE.ID " +
            "LEFT JOIN UM_RESOURCE_NAMESPACE AS RESOURCE_NAMESPACE ON UM_RESOURCE.NAMESPACE_ID = " +
                    "RESOURCE_NAMESPACE.ID " +
            "LEFT JOIN UM_ACTION ON UM_PERMISSION.ACTION_ID = UM_ACTION.ID " +
            "LEFT JOIN UM_RESOURCE_NAMESPACE AS ACTION_NAMESPACE ON UM_ACTION.NAMESPACE_ID = " +
                    "ACTION_NAMESPACE.ID " +
            "WHERE UM_PERMISSION.ID IN (SELECT PERMISSION_ID " +
                                       "FROM UM_ROLE_PERMISSION " +
                                       "WHERE ROLE_ID = (SELECT ID " +
                                                        "FROM UM_ROLE " +
                                                        "WHERE ROLE_UNIQUE_ID = :role_id;)) " +
            "AND UM_PERMISSION.RESOURCE_ID IN (SELECT ID FROM UM_RESOURCE " +
                                              "WHERE NAMESPACE_ID IN (SELECT ID " +
                                                                     "FROM UM_RESOURCE_NAMESPACE " +
                                                                     "WHERE NAMESPACE LIKE :resource_namespace;) " +
                                              "AND RESOURCE_NAME LIKE :resource_name;)";

    private static final String GET_ROLES_FOR_GROUP =
            "SELECT ROLE_NAME, ROLE_UNIQUE_ID " +
            "FROM UM_ROLE " +
            "WHERE ID IN (SELECT ROLE_ID " +
                        "FROM UM_GROUP_ROLE " +
                        "WHERE GROUP_UNIQUE_ID = :group_id;)";

    private static final String LIST_GROUP_BY_ATTRIBUTE =
            "SELECT UM_GROUP.USER_UNIQUE_ID " +
            "FROM UM_GROUP LEFT JOIN UM_GROUP_ATTRIBUTES " +
            "ON UM_GROUP_ATTRIBUTES.GROUP_ID = UM_GROUP.ID " +
            "WHERE UM_GROUP_ATTRIBUTES.ATTR_ID = " +
                    "(SELECT ID " +
                    "FROM UM_ATTRIBUTES " +
                    "WHERE ATTR_NAME = :attr_name; ) " +
            "AND UM_GROUP_ATTRIBUTES.ATTR_VALUE LIKE :attr_value; " +
            "LIMIT :length; " +
            "OFFSET :offset;";

    private static final String ADD_PERMISSION =
            "INSERT INTO UM_PERMISSION (RESOURCE_ID, ACTION_ID, PERMISSION_UNIQUE_ID) " +
            "VALUES (:resource_id;, :action_id;, :permission_id;)";

    private static final String ADD_ROLE =
            "INSERT INTO UM_ROLE (ROLE_NAME, ROLE_UNIQUE_ID) " +
            "VALUES (:role_name;, :role_unique_id;)";

    private static final String ADD_PERMISSION_TO_ROLE =
            "INSERT INTO UM_ROLE_PERMISSION (ROLE_ID, PERMISSION_ID) " +
            "VALUES (:role_id;, " +
                    "(SELECT ID " +
                    "FROM UM_PERMISSION " +
                    "WHERE PERMISSION_UNIQUE_ID = :permission_id;))";

    private static final String GET_USERS_OF_ROLE =
            "SELECT USER_UNIQUE_ID " +
            "FROM UM_USER_ROLE " +
            "WHERE ROLE_ID = (SELECT ID " +
                             "FROM UM_ROLE " +
                             "WHERE ROLE_UNIQUE_ID = :role_id;)";

    private static final String GET_GROUPS_OF_ROLE =
            "SELECT GROUP_UNIQUE_ID " +
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
            "AND ROLE_ID = (SELECT ID " +
                           "FROM UM_ROLE " +
                           "WHERE ROLE_NAME = :role_name;)";

    private static final String IS_GROUP_IN_ROLE =
            "SELECT ID " +
            "FROM UM_GROUP_ROLE " +
            "WHERE GROUP_UNIQUE_ID = :group_id; " +
            "AND ROLE_ID = (SELECT ID " +
                           "FROM UM_ROLE " +
                           "WHERE ROLE_NAME = :role_name;)";

    private static final String DELETE_ROLES_OF_USER =
            "DELETE FROM UM_USER_ROLE " +
            "WHERE USER_UNIQUE_ID = :user_id; ";

    private static final String ADD_ROLES_TO_USER =
            "INSERT INTO UM_USER_ROLE(USER_UNIQUE_ID, ROLE_ID) " +
            "VALUES (:user_id;, (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;))";

    private static final String ADD_ROLES_TO_GROUP =
            "INSERT INTO UM_GROUP_ROLE(GROUP_UNIQUE_ID, ROLE_ID) " +
            "VALUES (:group_id;, (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;))";

    private static final String ADD_PERMISSION_TO_ROLE_BY_UNIQUE_ID =
            "INSERT INTO UM_ROLE_PERMISSION (ROLE_ID, PERMISSION_ID)" +
                    "VALUES (" +
                    "(SELECT ID " +
                    "FROM UM_ROLE " +
                    "WHERE ROLE_UNIQUE_ID = :role_id;), " +
                    "(SELECT ID " +
                    "FROM UM_PERMISSION " +
                    "WHERE PERMISSION_UNIQUE_ID = :permission_id;))";

    private static final String DELETE_ROLES_FROM_GROUP =
            "DELETE FROM UM_GROUP_ROLE " +
            "WHERE GROUP_UNIQUE_ID = :group_id; ";

    private static final String DELETE_GROUPS_FROM_ROLE =
            "DELETE FROM UM_GROUP_ROLE WHERE ROLE_ID = :role_id;";

    private static final String DELETE_USERS_OF_ROLE =
            "DELETE FROM UM_USER_ROLE WHERE ROLE_ID = :role_id;";

    private static final String DELETE_PERMISSIONS_FROM_ROLE =
            "DELETE FROM UM_ROLE_PERMISSION WHERE ROLE_ID = (SELECT ID " +
                                                            "FROM UM_ROLE " +
                                                            "WHERE ROLE_UNIQUE_ID = :role_id;)";

    private static final String DELETE_GIVEN_ROLES_FROM_USER =
            "DELETE FROM UM_USER_ROLE " +
            "WHERE USER_UNIQUE_ID = :user_id; " +
            "AND ROLE_ID = (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;)";

    private static final String DELETE_GIVEN_ROLES_FROM_GROUP =
            "DELETE FROM UM_GROUP_ROLE " +
            "WHERE GROUP_UNIQUE_ID = :group_id; " +
            "AND ROLE_ID = (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;)";

    private static final String DELETE_GIVEN_PERMISSIONS_FROM_ROLE =
            "DELETE FROM UM_ROLE_PERMISSION " +
            "WHERE ROLE_ID = (SELECT ID FROM UM_ROLE WHERE ROLE_UNIQUE_ID = :role_id;) " +
            "AND PERMISSION_ID = (SELECT ID FROM UM_PERMISSION WHERE PERMISSION_UNIQUE_ID = :permission_id;)";

    private static final String GET_PERMISSION =
            "SELECT UM_PERMISSION.PERMISSION_UNIQUE_ID, UM_RESOURCE.USER_UNIQUE_ID " +
            "FROM UM_PERMISSION LEFT JOIN UM_RESOURCE " +
            "ON UM_PERMISSION.RESOURCE_ID = UM_RESOURCE.ID " +
            "WHERE RESOURCE_ID = (SELECT ID " +
                                 "FROM UM_RESOURCE " +
                                 "WHERE NAMESPACE_ID = (SELECT ID " +
                                                       "FROM UM_RESOURCE_NAMESPACE " +
                                                       "WHERE NAMESPACE = :resource_namespace;) " +
                                 "AND RESOURCE_NAME = :resource_name;) " +
            "AND ACTION_ID = (SELECT ID " +
                             "FROM UM_ACTION " +
                             "WHERE NAMESPACE_ID = (SELECT ID " +
                                                   "FROM UM_RESOURCE_NAMESPACE " +
                                                   "WHERE NAMESPACE = :action_namespace;) " +
                             "AND ACTION_NAME = :action_name;) ";

    private static final String ADD_NAMESPACE =
            "INSERT INTO UM_RESOURCE_NAMESPACE(NAMESPACE, DESCRIPTION) " +
            "VALUES (:namespace;, :description;)";

    private static final String GET_NAMESPACE_ID =
            "SELECT ID FROM UM_RESOURCE_NAMESPACE " +
            "WHERE NAMESPACE = :namespace;";

    private static final String ADD_RESOURCE =
            "INSERT INTO UM_RESOURCE(NAMESPACE_ID, RESOURCE_NAME, USER_UNIQUE_ID) " +
            "VALUES (:namespace_id;, :resource_name;, :user_id;)";

    private static final String ADD_ACTION =
            "INSERT INTO UM_ACTION(NAMESPACE_ID, ACTION_NAME) " +
            "VALUES (:namespace_id;, :action_name;)";

    private static final String GET_RESOURCE_ID =
            "SELECT ID " +
            "FROM UM_RESOURCE " +
            "WHERE NAMESPACE_ID = (SELECT ID " +
                               "FROM UM_RESOURCE_NAMESPACE " +
                               "WHERE NAMESPACE = :resource_namespace;) " +
            "AND RESOURCE_NAME = :resource_name;";

    private static final String GET_ACTION_ID =
            "SELECT ID FROM UM_ACTION " +
            "WHERE NAMESPACE_ID = (SELECT ID " +
                                  "FROM UM_RESOURCE_NAMESPACE " +
                                  "WHERE NAMESPACE = :action_namespace;) " +
            "AND ACTION_NAME = :action_name;";

    private static final String GET_GROUP_ATTRIBUTES =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_GROUP_ATTRIBUTES LEFT JOIN UM_ATTRIBUTES " +
            "ON UM_GROUP_ATTRIBUTES.ATTR_ID = UM_ATTRIBUTES.ID" +
            "WHERE GROUP_ID = (SELECT GROUP_ID " +
                              "FROM UM_GROUP " +
                              "WHERE GROUP_UNIQUE_ID = :group_id;)";

    private static final String GET_GROUP_ATTRIBUTES_FROM_NAME =
            "SELECT ATTR_NAME, ATTR_VALUE " +
            "FROM UM_GROUP_ATTRIBUTES LEFT JOIN UM_ATTRIBUTES " +
            "ON UM_GROUP_ATTRIBUTES.ATTR_ID = UM_ATTRIBUTES.ID" +
            "WHERE GROUP_ID = (SELECT ID " +
                              "FROM UM_GROUP " +
                              "WHERE GROUP_UNIQUE_ID = :group_id;) " +
            "AND ATTR_NAME IN (:attr_names;)";

    private static final String GET_PERMISSIONS_FROM_ACTION_FOR_ROLE =
            "SELECT RESOURCE_NAMESPACE.NAMESPACE, UM_RESOURCE.RESOURCE_NAME, UM_RESOURCE.USER_UNIQUE_ID, " +
                    "ACTION_NAMESPACE.NAMESPACE, UM_ACTION.ACTION_NAME, UM_PERMISSION.PERMISSION_UNIQUE_ID " +
            "FROM UM_PERMISSION " +
            "LEFT JOIN UM_RESOURCE ON UM_PERMISSION.RESOURCE_ID = UM_RESOURCE.ID " +
            "LEFT JOIN UM_RESOURCE_NAMESPACE AS RESOURCE_NAMESPACE ON UM_RESOURCE.NAMESPACE_ID = " +
                    "RESOURCE_NAMESPACE.ID " +
            "LEFT JOIN UM_ACTION ON UM_PERMISSION.ACTION_ID = UM_ACTION.ID " +
            "LEFT JOIN UM_RESOURCE_NAMESPACE AS ACTION_NAMESPACE ON UM_ACTION.NAMESPACE_ID = " +
                    "ACTION_NAMESPACE.ID " +
            "WHERE UM_PERMISSION.ID IN (SELECT PERMISSION_ID " +
                                       "FROM UM_ROLE_PERMISSION " +
                                       "WHERE ROLE_ID = (SELECT ID " +
                                                        "FROM UM_ROLE " +
                                                        "WHERE ROLE_UNIQUE_ID = :role_id;)) " +
            "AND UM_PERMISSION.ACTION_ID IN (SELECT ID FROM UM_ACTION " +
                                            "WHERE NAMESPACE_ID IN (SELECT ID " +
                                                                   "FROM UM_RESOURCE_NAMESPACE " +
                                                                   "WHERE NAMESPACE LIKE :action_namespace;) " +
                                            "AND RESOURCE_NAME LIKE :action_name;)";

    private static final String COUNT_ROLES = "SELECT COUNT(*) FROM UM_ROLE";

    private static final String COUNT_PERMISSIONS = "SELECT COUNT(*) FROM UM_PERMISSION";

    private static final String COUNT_USERS = "SELECT COUNT(*) FROM UM_USER";

    private static final String COUNT_GROUPS = "SELECT COUNT(*) FROM UM_GROUP";

    private static final String GET_RESOURCES =
            "SELECT UM_RESOURCE_N.NAMESPACE, RESOURCE_NAME, USER_UNIQUE_ID " +
            "FROM UM_RESOURCE " +
            "JOIN UM_RESOURCE_NAMESPACE AS UM_RESOURCE_N ON UM_RESOURCE_N.ID = UM_RESOURCE.NAMESPACE_ID " +
            "WHERE RESOURCE_NAME LIKE :resource_name;";

    private static final String GET_ACTIONS =
            "SELECT UM_RESOURCE_N.NAMESPACE, ACTION_NAME " +
            "FROM UM_ACTION " +
            "JOIN UM_RESOURCE_NAMESPACE AS UM_RESOURCE_N ON UM_RESOURCE_N.ID = UM_ACTION.NAMESPACE_ID " +
            "WHERE ACTION_NAME LIKE :action_name;";

    private static final String LIST_ROLES =
            "SELECT ROLE_NAME, ROLE_UNIQUE_ID " +
            "FROM UM_ROLE " +
            "WHERE ROLE_NAME LIKE :role_name; " +
            "LIMIT :length; OFFSET :offset;";

    private static final String LIST_PERMISSIONS =
            "SELECT RESOURCE_N.NAMESPACE AS RESOURCE_NAMESPACE, " +
                    "UM_RESOURCE.RESOURCE_NAME, UM_RESOURCE.USER_UNIQUE_ID, " +
                    "ACTION_N.NAMESPACE AS ACTION_NAMESPACE, UM_ACTION.ACTION_NAME, " +
                    "UM_PERMISSION.PERMISSION_UNIQUE_ID " +
            "FROM UM_PERMISSION " +
            "JOIN UM_RESOURCE ON UM_PERMISSION.RESOURCE_ID = UM_RESOURCE.ID " +
            "JOIN UM_ACTION ON UM_PERMISSION.ACTION_ID = UM_ACTION.ID " +
            "JOIN UM_RESOURCE_NAMESPACE AS RESOURCE_N ON UM_RESOURCE.NAMESPACE_ID = RESOURCE_N.ID " +
            "JOIN UM_RESOURCE_NAMESPACE AS ACTION_N ON UM_ACTION.NAMESPACE_ID = ACTION_N.ID " +
            "WHERE UM_RESOURCE.RESOURCE_NAME " +
            "LIKE :resource_name; AND UM_ACTION.ACTION_NAME LIKE :action_name; " +
            "LIMIT :length; OFFSET :offset;";

    private static final String DELETE_RESOURCE =
            "DELETE FROM UM_RESOURCE " +
            "WHERE RESOURCE_NAME = :resource_name; " +
            "AND NAMESPACE_ID = (SELECT ID FROM UM_RESOURCE_NAMESPACE " +
                                "WHERE NAMESPACE = :resource_namespace;)";

    private static final String DELETE_ACTION =
            "DELETE FROM UM_ACTION " +
            "WHERE ACTION_NAME = :action_name; " +
            "AND NAMESPACE_ID = (SELECT ID FROM UM_RESOURCE_NAMESPACE " +
                                "WHERE NAMESPACE = :resource_namespace;)";

    public MySQLFamilySQLQueryFactory() {

        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COMPARE_PASSWORD_HASH, COMPARE_PASSWORD_HASH);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_FROM_ATTRIBUTE, GET_USER_FROM_ATTRIBUTE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_FROM_ATTRIBUTE, GET_GROUP_FROM_ATTRIBUTE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_USER_ATTRIBUTES, GET_USER_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_USER, DELETE_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_GROUP, DELETE_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER, ADD_USER);
//        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_CLAIMS, ADD_USER_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_USER_GROUPS, ADD_USER_GROUPS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_USERS_BY_ATTRIBUTE, LIST_USERS_BY_ATTRIBUTE);
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
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_IS_USER_IN_GROUP, IS_USER_IN_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLE, GET_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_USER, GET_ROLES_FOR_USER);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSIONS_FROM_RESOURCE_FOR_ROLE,
                GET_PERMISSIONS_FROM_RESOURCE_FOR_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ROLES_FOR_GROUP, GET_ROLES_FOR_GROUP);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_GROUP_BY_ATTRIBUTE, LIST_GROUP_BY_ATTRIBUTE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSION, ADD_PERMISSION);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ROLE, ADD_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE, ADD_PERMISSION_TO_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_PERMISSIONS_TO_ROLE_BY_UNIQUE_ID,
                ADD_PERMISSION_TO_ROLE_BY_UNIQUE_ID);
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
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSION, GET_PERMISSION);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_RESOURCE_ID, GET_RESOURCE_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_RESOURCE, ADD_RESOURCE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ACTION_ID, GET_ACTION_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_ACTION, ADD_ACTION);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_ATTRIBUTES, GET_GROUP_ATTRIBUTES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_GROUP_ATTRIBUTES_FROM_NAME,
                GET_GROUP_ATTRIBUTES_FROM_NAME);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_PERMISSIONS_FROM_ACTION_FOR_ROLE,
                GET_PERMISSIONS_FROM_ACTION_FOR_ROLE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_NAMESPACE_ID, GET_NAMESPACE_ID);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_ADD_NAMESPACE, ADD_NAMESPACE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COUNT_ROLES, COUNT_ROLES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COUNT_PERMISSIONS, COUNT_PERMISSIONS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COUNT_USERS, COUNT_USERS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_COUNT_GROUPS, COUNT_GROUPS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_RESOURCES, GET_RESOURCES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_GET_ACTIONS, GET_ACTIONS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_ROLES, LIST_ROLES);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_LIST_PERMISSIONS, LIST_PERMISSIONS);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_RESOURCE, DELETE_RESOURCE);
        sqlQueries.put(ConnectorConstants.QueryTypes.SQL_QUERY_DELETE_ACTION, DELETE_ACTION);
    }
}
