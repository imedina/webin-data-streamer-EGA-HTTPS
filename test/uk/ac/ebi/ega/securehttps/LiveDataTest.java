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

import java.net.MalformedURLException;
import java.net.URL;
import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author asenf
 */
public class LiveDataTest {
    static LiveData ld;

    public LiveDataTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
        ld = null;
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
        ld = null;
    }

    /**
     * Test of LiveData method, of class LiveData.
     */
    @Test
    public void testLiveData_0args() {
        System.out.println(" * LiveData.LiveData()");
        
        LiveData result = LiveData.LiveData();

        assertNotNull(result); // Returns an actual instance, not Null
        
        assertNull(ld);
        ld = LiveData.LiveData(); // Works for static class variable
        assertNotNull(ld);
        
        ld = null; // Reset test
    }

    /**
     * Test of LiveData method, of class LiveData.
     */
    @Test
    public void testLiveData_LiveStruct_String() {
        System.out.println(" * LiveData.LiveData(...)");
        
        String session_token = "TestToken";
        LiveStruct input = null;
        try {
            input = sampleStruct(session_token);
        } catch (MalformedURLException ex) {
            Logger.getLogger(LiveDataTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        assertNotNull(input);
        assertEquals(session_token, input.session_token);
    
        assertNull(LiveDataTest.ld);
        LiveDataTest.ld = LiveData.LiveData(input, session_token);
        assertNotNull(LiveDataTest.ld);
        assertTrue(LiveDataTest.ld.containsKey(session_token));
        
        LiveStruct returned = LiveDataTest.ld.get(session_token);
        assertEquals(input, returned); // Final test - what comes out equals when went in :-)
    }

    /**
     * Test of clone method, of class LiveData.
     */
    @Test
    public void testClone() throws Exception {
        System.out.println(" * LiveData.clone");
        
        if (LiveDataTest.ld == null) {
            String session_token = "TestToken";
            LiveStruct input = null;
            try {
                input = sampleStruct(session_token);
            } catch (MalformedURLException ex) {
                Logger.getLogger(LiveDataTest.class.getName()).log(Level.SEVERE, null, ex);
            }

            LiveDataTest.ld = LiveData.LiveData(input, session_token);
        }
        
        Object result = null;

        try {
            result = LiveDataTest.ld.clone();
        } catch (CloneNotSupportedException ex) {
            assertTrue(true);
            return;
        } 
        
        // This is an exception test. Cloning is supposed to throw an exception.
        // No exception would be an error message.
        assertFalse(true);
    }

    /**
     * Test of put method, of class LiveData.
     */
    @Test
    public void testPut() {
        System.out.println(" * LiveData.put");
        
        LiveDataTest.ld = null;
        assertNull(LiveDataTest.ld);
        LiveDataTest.ld = LiveData.LiveData();
        assertNotNull(LiveDataTest.ld);
        
        String session_token = "TestToken";
        LiveStruct input = null;
        try {
            input = sampleStruct(session_token);
        } catch (MalformedURLException ex) {
            Logger.getLogger(LiveDataTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        assertNotNull(input);
        assertEquals(session_token, input.session_token);
    
        LiveDataTest.ld.put(session_token, input);
        assertTrue(LiveDataTest.ld.containsKey(session_token));
        
        LiveStruct returned = LiveDataTest.ld.get(session_token);
        assertEquals(input, returned); // Final test - what comes out equals when went in :-)
    }

    /**
     * Test of get method, of class LiveData.
     */
    @Test
    public void testGet() {
        System.out.println(" * LiveData.get");
        System.out.println("    Same test as put (so it's skipped)");
    }

    /**
     * Test of containsKey method, of class LiveData.
     */
    @Test
    public void testContainsKey() {
        System.out.println(" * LiveData.containsKey");
        System.out.println("    Same test as put (so it's skipped)");
    }

    /**
     * Test of update method, of class LiveData.
     */
    @Test
    public void testUpdate() {
        System.out.println(" * LiveData.update");
        
        String session_token = "TestToken";
        LiveStruct input = null;
        try {
            input = sampleStruct(session_token);
        } catch (MalformedURLException ex) {
            Logger.getLogger(LiveDataTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        LiveDataTest.ld.put(session_token, input);
        
        LiveStruct returned = LiveDataTest.ld.get(session_token);
        assertEquals(input.BAI_path, returned.BAI_path);

        returned.BAI_path = "A completely new path!";
        LiveDataTest.ld.update(session_token, returned);
        
        LiveStruct mod_returned = LiveDataTest.ld.get(session_token);
        assertEquals("A completely new path!", mod_returned.BAI_path);
    }
    
    // *************************************************************************
    // *************************************************************************

    // Just used to populate some data to enable testing of the HashMap structure
    private static LiveStruct sampleStruct(String sessionToken) throws MalformedURLException {
        LiveStruct ls = new LiveStruct();
        
        ls.BAI_file = new File("nonexistent.bai");
        ls.BAI_path = "SamplePath";
        ls.BAM_File = new File("nonexistent.bam");
        ls.BAM_url = new URL("http://nonexistant");        
        ls.session_token = sessionToken;
        ls.user_password = "password".getBytes();
        ls.username = "JUnit_Tester";

        return ls;
    }
}
