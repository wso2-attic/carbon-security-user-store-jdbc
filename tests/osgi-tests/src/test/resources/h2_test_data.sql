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


INSERT INTO UM_USER (USER_UNIQUE_ID)
VALUES ('41dadd2aea6e11e59ce95e5517507c66'),
  ('b5572242139d11e6a1483e1d05defe78'),
  ('b5572580139d11e6a1483e1d05defe78'),
  ('darshana');

INSERT INTO UM_ATTRIBUTES (ATTR_NAME)
VALUES ('username'),
  ('email'),
  ('firstname'),
  ('lastname'),
  ('reportsto');

INSERT INTO UM_PASSWORD (PASSWORD, USER_UNIQUE_ID)
VALUES ('3opCozpRixH6BvSXyr0513v1nyFWpdcQy7F6r6P/LFE=', '41dadd2aea6e11e59ce95e5517507c66'),
  ('3opCozpRixH6BvSXyr0513v1nyFWpdcQy7F6r6P/LFE=', 'b5572242139d11e6a1483e1d05defe78'),
  ('3opCozpRixH6BvSXyr0513v1nyFWpdcQy7F6r6P/LFE=', 'b5572580139d11e6a1483e1d05defe78');

INSERT INTO UM_PASSWORD_INFO (PASSWORD_SALT, HASH_ALGO, ITERATION_COUNT, KEY_LENGTH, USER_UNIQUE_ID)
VALUES ('1ff1188e-f1bf-11e5-9ce9-5e5517507c66', 'SHA256', 4096, 256, '41dadd2aea6e11e59ce95e5517507c66');

INSERT INTO UM_GROUP (GROUP_UNIQUE_ID)
VALUES ('a422aa98ecf411e59ce95e5517507c66'),
  ('16231aee15a711e6a1483e1d05defe78'),
  ('16231f8a15a711e6a1483e1d05defe78'),
  ('162321d815a711e6a1483e1d05defe78'),
  ('sales'),
  ('productleads');

INSERT INTO UM_ROLE (ROLE_NAME, ROLE_UNIQUE_ID)
VALUES ('admin', '985b79ecfcdf11e586aa5e5517507c66'),
  ('guest', 'df813f5e105e11e6a1483e1d05defe78'),
  ('general', '70e2e088105f11e6a1483e1d05defe78'),
  ('role1', '7f8adbe6134c11e6a1483e1d05defe78'),
  ('role2', '7f8ade5c134c11e6a1483e1d05defe78'),
  ('role3', '7f8adf56134c11e6a1483e1d05defe78'),
  ('role4', '7f8ae028134c11e6a1483e1d05defe78'),
  ('role5', '7f8ae2a8134c11e6a1483e1d05defe78');

INSERT INTO UM_RESOURCE_NAMESPACE (NAMESPACE, DESCRIPTION)
VALUES ('reg', 'Represents a registry resource/action');

INSERT INTO UM_RESOURCE (NAMESPACE_ID, RESOURCE_NAME, USER_UNIQUE_ID)
VALUES (1, 'root/resource/id', '41dadd2aea6e11e59ce95e5517507c66'),
  (1, 'root/resource/name', '41dadd2aea6e11e59ce95e5517507c66'),
  (1, 'root/resource/delete', '41dadd2aea6e11e59ce95e5517507c66');

INSERT INTO UM_ACTION (NAMESPACE_ID, ACTION_NAME)
VALUES (1, 'add'),
  (1, 'delete'),
  (1, 'update'),
  (1, 'action1'),
  (1, 'action2'),
  (1, 'action3');

INSERT INTO UM_PERMISSION (RESOURCE_ID, ACTION_ID, PERMISSION_UNIQUE_ID)
VALUES (1, 1, 'f61a1c240df011e6a1483e1d05defe78'),
  (1, 2, '64335ff4106211e6a1483e1d05defe78'),
  (1, 3, 'e890bfd0135011e6a1483e1d05defe78'),
  (2, 4, 'e890c548135011e6a1483e1d05defe78'),
  (2, 5, 'e890c688135011e6a1483e1d05defe78');

INSERT INTO UM_USER_GROUP (USER_ID, GROUP_ID)
VALUES ('1', '1');

INSERT INTO UM_USER_ATTRIBUTES (ATTR_ID, ATTR_VALUE, USER_ID)
VALUES ((SELECT ID
         FROM UM_ATTRIBUTES
         WHERE UM_ATTRIBUTES.ATTR_NAME = 'firstname'), 'Jayanga', 1),
  ((SELECT ID
    FROM UM_ATTRIBUTES
    WHERE UM_ATTRIBUTES.ATTR_NAME = 'lastname'), 'Kaushalya', 1);

INSERT INTO UM_ROLE_PERMISSION (ROLE_ID, PERMISSION_ID)
VALUES ('1', '1'), ('1', '2'), ('1', '3'), ('1', '4'),
  ('2', '2'), ('2', '1'), ('2', '3'), ('2', '4'),
  ('3', '3'), ('3', '1'), ('3', '2'), ('3', '4'),
  ('4', '4'), ('4', '1'), ('4', '2'), ('4', '3');

INSERT INTO UM_USER_ROLE (USER_UNIQUE_ID, ROLE_ID)
VALUES ('41dadd2aea6e11e59ce95e5517507c66', '1'),
  ('41dadd2aea6e11e59ce95e5517507c66', '2'),
  ('41dadd2aea6e11e59ce95e5517507c66', '3');

INSERT INTO UM_GROUP_ROLE (GROUP_UNIQUE_ID, ROLE_ID)
VALUES ('a422aa98ecf411e59ce95e5517507c66', '1'),
  ('a422aa98ecf411e59ce95e5517507c66', '2'),
  ('a422aa98ecf411e59ce95e5517507c66', '3');
