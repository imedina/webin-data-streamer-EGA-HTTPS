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

import java.util.HashMap;

/**
 *
 * @author asenf
 *
 * This class collects live data as the server runs (auth, pw)
 * needed to stay consistent with multiple independent URL connections across
 * various sessions.
 *
 * Implemented as singleton; only one instance must exist to be useful in sharing data
 * between threads;
 */
public class LiveData {
    private static LiveData ref;

    private HashMap sessionData = null;

    private LiveData() {
        this.sessionData = new HashMap();
    }
    private LiveData(LiveStruct input, String session_token) {
        if (this.sessionData == null) {
            this.sessionData = new HashMap();
        }

        this.sessionData.put(session_token, input);
    }

    public static LiveData LiveData() {
        if (ref == null)
            ref = new LiveData();
        return ref;
    }
    public static LiveData LiveData(LiveStruct input, String session_token) {
        if (ref == null)
            ref = new LiveData(input, session_token);
        else if (!ref.containsKey(session_token))
            ref.put(session_token, input);
        return ref;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    // *************************************************************************
    // *************************************************************************

    public synchronized void put(String session_token, LiveStruct input) {
        ref.sessionData.put(session_token, input);
    }

    public synchronized LiveStruct get(String session_token) {
        return (LiveStruct)ref.sessionData.get(session_token);
    }

    public synchronized boolean containsKey(String key) {
        return ref.sessionData.containsKey(key);
    }

    public synchronized void update(String session_token, LiveStruct updated_data) {
        ref.sessionData.remove(session_token);
        ref.sessionData.put(session_token, updated_data);
    }
}
