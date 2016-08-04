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

import org.wso2.carbon.security.caas.user.core.exception.StoreException;
import org.wso2.carbon.security.caas.user.core.util.PasswordHandler;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Default implementation of the password handler.
 */
public class DefaultPasswordHandler implements PasswordHandler {

    private static final String KEY_FACTORY_ALGO_HEAD = "PBKDF2WithHmac";

    private int iterationCount = 4096;
    private int keyLength = 256;

    /**
     * Hash the given password using given algorithm.
     * @param password Password to be hashed.
     * @param salt Salt to be used to hash the password.
     * @param hashAlgo Hashing algorithm to be used. (SHA1, SHA224, SHA256, SHA384, SHA512)
     * @return Hash as a <code>String</code>
     * @throws NoSuchAlgorithmException No such algorithm exception.
     */
    @Override
    public String hashPassword(char[] password, String salt, String hashAlgo) throws NoSuchAlgorithmException {

        String keyFactoryAlgorithm = KEY_FACTORY_ALGO_HEAD + hashAlgo.toUpperCase(Locale.ENGLISH);

        KeySpec keySpec = new PBEKeySpec(password, salt.getBytes(Charset.forName("UTF-8")), iterationCount,
                keyLength);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(keyFactoryAlgorithm);

        try {
            byte[] hash = secretKeyFactory.generateSecret(keySpec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (InvalidKeySpecException e) {
            throw new StoreException("Invalid key specification.", e);
        }
    }

    @Override
    public void setIterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
    }

    @Override
    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }
}
