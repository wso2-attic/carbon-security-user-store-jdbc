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

/* NOTE: Use VARCHAR(255) instead of VARCHAR(256) if the length needed is less than 256. Because 256 will require
 * two bytes to store the VARCHAR character length.
 */

CREATE TABLE UM_TENANT
(
  ID          INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  DOMAIN_NAME VARCHAR(255)                       NOT NULL
);

CREATE TABLE UM_USER
(
  ID                  INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  USER_UNIQUE_ID      VARCHAR(64)                        NOT NULL,
  USERNAME            VARCHAR(255)                       NOT NULL,
  IDENTITY_STORE_ID   VARCHAR(255)                       NOT NULL,
  CREDENTIAL_STORE_ID VARCHAR(255)                       NOT NULL,
  TENANT_ID           INTEGER                            NOT NULL,
  FOREIGN KEY (TENANT_ID) REFERENCES UM_TENANT (ID)
);
CREATE UNIQUE INDEX "unique_USERNAME_INDEX_1" ON UM_USER (USERNAME);

CREATE TABLE UM_GROUP
(
  ID              INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  GROUP_NAME      VARCHAR(255)                       NOT NULL,
  GROUP_UNIQUE_ID VARCHAR(64)                        NOT NULL,
  TENANT_ID       INTEGER                            NOT NULL,
  FOREIGN KEY (TENANT_ID) REFERENCES UM_TENANT (ID)
);

CREATE TABLE UM_ROLE
(
  ID             INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  ROLE_UNIQUE_ID VARCHAR(64)                        NOT NULL,
  ROLE_NAME      VARCHAR(255)                       NOT NULL
);

CREATE TABLE UM_RESOURCE
(
  ID                INTEGER AUTO_INCREMENT NOT NULL,
  DOMAIN_ID         VARCHAR(10)            NOT NULL,
  RESOURCE_NAME     VARCHAR(255)           NOT NULL,
  USER_UNIQUE_ID    VARCHAR(64)            NOT NULL,
  IDENTITY_STORE_ID VARCHAR(255)           NOT NULL,
  CONSTRAINT RESOURCE_CPK PRIMARY KEY (DOMAIN_ID, RESOURCE_NAME)
);

CREATE TABLE UM_ACTION
(
  ID          INTEGER AUTO_INCREMENT NOT NULL,
  DOMAIN_ID   VARCHAR(10)            NOT NULL,
  ACTION_NAME VARCHAR(255)           NOT NULL,
  CONSTRAINT ACTION_CPK PRIMARY KEY (DOMAIN_ID, ACTION_NAME)
);

CREATE TABLE UM_PERMISSION
(
  ID                   INTEGER AUTO_INCREMENT NOT NULL,
  RESOURCE_ID          INTEGER                NOT NULL,
  ACTION_ID            INTEGER                NOT NULL,
  PERMISSION_UNIQUE_ID VARCHAR(64)            NOT NULL,

  CONSTRAINT PERMISSION_CPK PRIMARY KEY (RESOURCE_ID, ACTION_ID),
  FOREIGN KEY (RESOURCE_ID) REFERENCES UM_RESOURCE (ID) ON DELETE CASCADE,
  FOREIGN KEY (ACTION_ID) REFERENCES UM_ACTION (ID) ON DELETE CASCADE
);

CREATE TABLE UM_USER_ATTRIBUTES
(
  ID         INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  ATTR_NAME  VARCHAR(255)                       NOT NULL,
  ATTR_VALUE VARCHAR(1024)                      NOT NULL,
  USER_ID    INTEGER                            NOT NULL,
  FOREIGN KEY (USER_ID) REFERENCES UM_USER (ID) ON DELETE CASCADE
);

CREATE TABLE UM_PASSWORD
(
  ID                INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  PASSWORD          VARCHAR(88)                        NOT NULL,
  USER_UNIQUE_ID    VARCHAR(64)                        NOT NULL,
  IDENTITY_STORE_ID VARCHAR(255)                       NOT NULL
);

CREATE TABLE UM_PASSWORD_INFO
(
  ID                INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  PASSWORD_SALT     VARCHAR(64)                        NOT NULL,
  HASH_ALGO         VARCHAR(128)                       NOT NULL,
  ITERATION_COUNT   INT,
  KEY_LENGTH        INT,
  USER_UNIQUE_ID    VARCHAR(64)                        NOT NULL,
  IDENTITY_STORE_ID VARCHAR(255)                       NOT NULL
);

CREATE TABLE UM_USER_ROLE
(
  ID                INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  USER_UNIQUE_ID    VARCHAR(64)                        NOT NULL,
  IDENTITY_STORE_ID VARCHAR(255)                       NOT NULL,
  ROLE_ID           INTEGER                            NOT NULL,
  FOREIGN KEY (ROLE_ID) REFERENCES UM_ROLE (ID) ON DELETE CASCADE
);

CREATE TABLE UM_USER_GROUP
(
  ID       INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  USER_ID  INTEGER                            NOT NULL,
  GROUP_ID INTEGER                            NOT NULL,
  FOREIGN KEY (GROUP_ID) REFERENCES UM_GROUP (ID) ON DELETE CASCADE,
  FOREIGN KEY (USER_ID) REFERENCES UM_USER (ID) ON DELETE CASCADE
);

CREATE TABLE UM_GROUP_ROLE
(
  ID                INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  GROUP_UNIQUE_ID   VARCHAR(64)                        NOT NULL,
  IDENTITY_STORE_ID VARCHAR(255)                       NOT NULL,
  ROLE_ID           INTEGER                            NOT NULL,
  FOREIGN KEY (ROLE_ID) REFERENCES UM_ROLE (ID) ON DELETE CASCADE
);

CREATE TABLE UM_ROLE_PERMISSION
(
  ID            INTEGER AUTO_INCREMENT PRIMARY KEY NOT NULL,
  ROLE_ID       INTEGER                            NOT NULL,
  PERMISSION_ID INTEGER                            NOT NULL,
  FOREIGN KEY (PERMISSION_ID) REFERENCES UM_PERMISSION (ID) ON DELETE CASCADE,
  FOREIGN KEY (ROLE_ID) REFERENCES UM_ROLE (ID) ON DELETE CASCADE
);
