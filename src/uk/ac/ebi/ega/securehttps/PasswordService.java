/*********************************************************************************
 * 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * 
 *********************************************************************************/

package uk.ac.ebi.ega.securehttps;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.misc.BASE64Encoder;

public final class PasswordService
{
    private static PasswordService instance;

    private PasswordService()
    {
    }

    public synchronized String encrypt(String plaintext) {
        MessageDigest md = null;
        try
        {
            md = MessageDigest.getInstance("SHA-256"); //step 2
        }
        catch(NoSuchAlgorithmException ex)
        {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        }
        try
        {
            md.update(plaintext.getBytes("UTF-8")); //step 3
        }
        catch(UnsupportedEncodingException ex)
        {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        }

        byte raw[] = md.digest(); //step 4
        String hash = (new BASE64Encoder()).encode(raw); //step 5
        return hash; //step 6
    }
    public synchronized byte[] encrypt(byte[] plaintext) {
        MessageDigest md = null;
        try
        {
            md = MessageDigest.getInstance("SHA-256"); //step 2
        }
        catch(NoSuchAlgorithmException ex)
        {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        }
        md.update(plaintext); //step 3

        byte raw[] = md.digest(); //step 4
        return raw; //step 6
    }

    public static synchronized PasswordService getInstance() //step 1
    {
        if(instance == null)
        {
            instance = new PasswordService();
        }
        return instance;
    }
}