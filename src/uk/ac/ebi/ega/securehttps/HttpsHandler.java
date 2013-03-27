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

import com.mchange.v2.c3p0.ComboPooledDataSource;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import java.net.Socket;
import java.net.URL;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.transform.TransformerFactory;
import net.sf.samtools.seekablestream.SeekableFileStream;
import net.sf.samtools.seekablestream.SeekableHTTPStream;

import org.apache.commons.io.IOUtils;
import uk.ac.ebi.ega.cipher.Glue;
import uk.ac.ebi.ega.cipher.SeekableCipherStream_256;


/**
 *
 * @author asenf 25-02-2011
 *
 * This class is the primary 'worker' thread in this server. Here the secure connection
 * is established and requests are handled. The two main functions are:
 * 1 - User Authentication
 * 2 - Reply to Requests for BAM Data
 *
 * User credentials are kept in a separate class LiveData (indicating that it only
 * stores "live" data, in memory for the time it is needed). LiveData is shared between
 * worker threads to allow for user sessions across multiple individual HTTP requests.
 *
 * Each individual HTTP request (authentication or request for BAM data) is its own thread.
 *
 * TODO: Write/Read DOM cookie for each session to properly work with load balancers
 *
 */
public class HttpsHandler extends Thread {
    // Should be the same across multiple threads - it's the port defined at startup
    private Socket connectionsocket;
    private boolean verbose; // DEBUG ONLY
    private static LiveData inter_thread_store;
    private Connection conn, pw_conn;
    private ComboPooledDataSource cpds, pwds;
    private String ut, ft, pt;
    
    private HttpsServ server;

    // Constructor - receive an active socket connection once a request has been made
    public HttpsHandler(Socket connectionsocket, boolean verbose, LiveData inter_thread_store, Connection conn, Connection pw_conn, String ut_, String ft_, String pt_) {
        this.connectionsocket = connectionsocket; // accepted connection
        this.verbose = verbose;
        HttpsHandler.inter_thread_store = inter_thread_store; // authentication information
        this.conn = conn; // database connection
        this.pw_conn = pw_conn; // database connection
        this.cpds = null;
        this.pwds = null;
        this.ut = ut_;
        this.ft = ft_;
        this.pt = pt_;
    }

    // Constructor - receive an active socket connection once a request has been made
    public HttpsHandler(Socket connectionsocket, boolean verbose, LiveData inter_thread_store, ComboPooledDataSource cpds, ComboPooledDataSource pwds, String ut_, String ft_, String pt_) {
        this.connectionsocket = connectionsocket; // accepted connection
        this.verbose = verbose;
        HttpsHandler.inter_thread_store = inter_thread_store; // authentication information
        this.conn = null;
        this.pw_conn = null;
        this.cpds = cpds; // database connection
        this.pwds = pwds;
        this.ut = ut_;
        this.ft = ft_;
        this.pt = pt_;
    }
    
    public HttpsHandler(Socket connectionsocket, boolean verbose, LiveData inter_thread_store, HttpsServ server, String ut_, String ft_, String pt_) {
        this.connectionsocket = connectionsocket; // accepted connection
        this.verbose = verbose;
        HttpsHandler.inter_thread_store = inter_thread_store; // authentication information
        this.conn = null;
        this.pw_conn = null;
        this.cpds = null;
        this.pwds = null;
        this.server = server;
        this.ut = ut_;
        this.ft = ft_;
        this.pt = pt_;
    }

    //this is a overridden method from the Thread class we extended from
    @Override
    public void run() {
        try {
            // Has this host contacted the server before?
            String host = connectionsocket.getInetAddress().getCanonicalHostName().toString();
            if (this.verbose) {
                System.out.println("Accepted Connection from\t IP: " + connectionsocket.getInetAddress().toString() + "\t" + "Host: " + host);
            }

            // Read information provided by the client - distinguish "authenticate" and "request"
            BufferedReader in = new BufferedReader(new InputStreamReader(connectionsocket.getInputStream()));

            // Read session token - compare with storage in inter_thread_store - if present, then existing session
            String line1 = in.readLine(), command = "INVALID";
            if (this.verbose) System.out.println("First line: " + line1);
            StringTokenizer st = null;
            if (line1 != null) {
                st = new StringTokenizer(line1);
                command = st.nextToken();
            }

            // ****
            if (command != null && command.equalsIgnoreCase("POST")) { // Authentication - provides username/password
                post_request(in, host); // One thread per user/password!

            } else if (command != null && command.equalsIgnoreCase("GET")) { // Request - request BAM file section
                get_request(in, host, st); // request file (portion of..)

            } else { // Invalid Request
                // If neither GET nor POST were sent, this server will not respond.
                // Options include logging, doing nothing, sending error messages
                if (this.verbose) {
                    System.out.println("ILLEGAL REQUEST");
                    System.out.println("Request from " + host + " received that does not conform to specifications!");
                }
            }
            in.close();
            // *****************************************************************
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                connectionsocket.close();
            } catch (IOException ex) {
                Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }




    // *************************************************************************
    // Perform user authentication: connect to database and query user name
    //private ArrayList dataValidation(String username, byte[] password) {
    private ArrayList dataValidation(String username, String pw) {
        ArrayList result = null;
        boolean disconnect = false;

        try {
            this.conn = this.server.getAConn();
            this.pw_conn = this.server.getAPWConn();
            disconnect = true;
            
            // Request credentials -- compare user password with its hash in the database
            boolean success = false;
            String query = this.ut + "='"+username+"'";
            //String query = "SELECT "+this.ut[1]+", "+this.ut[3]+" FROM "+this.ut[0]+" WHERE "+this.ut[2]+"='"+username+"'";
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery(query);
            String user_id = null;
            while (rs.next())
            {
                String s = rs.getString(1), t = pw; // password
                String u = rs.getString(2); // user_id
                if (s.equals(t)) {
                    success = true;
                    user_id = u;
                    continue;
                }
            }

            if (success) {
                result = new ArrayList();
                username = user_id; //"1";
                query = this.ft + "='"+username+"'";
                //query = "SELECT "+this.ft[3]+", "+this.ft[4]+" FROM "+this.ft[0]+" WHERE "+this.ft[2]+"='"+username+"'";
                st = conn.createStatement();
                rs = st.executeQuery(query);
                while (rs.next())
                {
                    String s = rs.getString(1).trim(); // file_name
                    String r = rs.getString(2).trim(); //s + ".bai"; // index_name
                    File r_f = new File(r);
                    if (!r_f.exists()) continue; // Skip files without index
                    String q = get_pass_for_file(s);
                    
                    result.add(s);
                    result.add(r);
                    result.add(q);
                }
            }            

        } catch (SQLException ex) {
            Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
        }

        if (disconnect) {
            try {
                this.conn.close();
                this.conn = null;
            } catch (SQLException ex) {
                Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        return result;
    }
        private String get_pass_for_file(String filename) {
                String pw = "";
                try {
                        Connection conn = this.server.getAPWConn();
                        
                        String query = this.pt;
                        Statement st = conn.createStatement();
                        ResultSet rs = st.executeQuery(query);
                        
                        while (rs.next()) {
                                pw = rs.getString(1);
                                break;
                        }
                        
                        conn.close();
                } catch (SQLException ex) {
                        java.util.logging.Logger.getLogger(HttpsHandler.class.getName()).log(Level.SEVERE, null, ex);
                }

//System.out.println("PW " + pw);
                return pw;
        }




    // *****************************************************************
    // ** Authentication branch                                         
    // *****************************************************************
    // *************************************************************************
    // Perform user authentication request (branch of if statement)
    private void post_request(BufferedReader in, String host) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        GZIPOutputStream out__ = new GZIPOutputStream(connectionsocket.getOutputStream());
        String line1 = null;

        // This branch answers to POST connection requests - it expects a username/password
        // and established that the requesting client has indeed access. Then a session token
        // is generated and given to the client to indicate successful authentication for
        // future requests.
        while ((!(line1 = in.readLine()).equalsIgnoreCase(""))) {
//            if (this.verbose) System.out.println("--> " + line1);
        }
        line1 = in.readLine();
        if (line1 != null) {

            String username = line1.substring(line1.indexOf("=")+1, line1.indexOf(":"));
            String pw = line1.substring(line1.lastIndexOf("=")+1, line1.length());
            byte[] password = line1.substring(line1.lastIndexOf("=")+1, line1.length()).getBytes();
            // Think about: how to handle pw information here

            // Access Database - Validate User Credentials
            ArrayList valResult = dataValidation(username, pw), userResponse = null;
            HashMap user_files = null;
            if (valResult != null) { // if a list is returned, validation was successful
                // For now: Put it in the LiveData structure
                user_files = new HashMap();
                userResponse = new ArrayList();
                for (int i=0; i<valResult.size(); i+=3) {
                    String bam_url = valResult.get(i).toString();
                    if (!bam_url.toLowerCase().endsWith(".gpg")) {
                        String bai_url = valResult.get(i+1).toString();
                        String pass = valResult.get(i+2).toString();
                        String filename = bam_url.substring(bam_url.lastIndexOf("/")+1);

                        BAM_Entry x = new BAM_Entry(); // User's BAM files
                        x.BAM_url = bam_url;
                        x.BAI_url = bai_url;
                        x.pass = pass;
                        user_files.put(filename, x);
                        userResponse.add(filename);
                    }
                }

                // Build XML file for return to client
                TransformerFactory xformFactory = TransformerFactory.newInstance();



            } else { // validation not successful, or no files returned
                in.close();
                //out__.close();
                return;
            }

            // Send Server Response back to client
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            String session_token = String.valueOf(sr.nextGaussian()+"X"+sr.nextDouble()+"X"+sr.nextGaussian()+".bam"); // For SAMFileReader Interaction
            StringBuilder sb = new StringBuilder(); // TODO: potentially... proper header
            sb.append("Authentication_Success").append(" ").append(session_token).append(" \n").append("\n");

            // TODO -- append XML file to send to user


            // For now: Simply list all file names to the user
            if (userResponse != null) {
                for (int i=0; i<userResponse.size(); i++)
                    sb.append(userResponse.get(i).toString()).append("\n");
            }
System.out.println(sb.toString());
            out__.write(sb.toString().getBytes());
            out__.finish(); // complete the zlib stream
            out__.flush();

            // Update persistent storage -------------------------------
            LiveStruct new_session = new LiveStruct();
            new_session.session_token = session_token+host; // safe to be plain text (is it?)

            MessageDigest md5 = MessageDigest.getInstance("MD5"); // get the hash algorithm
            byte[] key = md5.digest(Glue.getInstance().GenerateRandomString(64, 64, 10, 10, 10, 10));// hash the pwd to make a 128bit key
            SecretKeySpec skey = new SecretKeySpec(key,"AES"); // create a key suitable for AES
            IvParameterSpec ivSpec = new IvParameterSpec(md5.digest(key)); // create an init vector (based on the key, hashed again)
            new_session.encipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            new_session.encipher.init(Cipher.ENCRYPT_MODE, skey, ivSpec);
            new_session.decipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            new_session.decipher.init(Cipher.DECRYPT_MODE, skey,ivSpec);
            skey = null; ivSpec = null;
            new_session.user_password = new_session.encipher.doFinal(password); // encrypted user password
            for (int i=0; i<password.length; password[i++] = 0); // Wipe password
            new_session.user_files = user_files; // All user's files and locations

            HttpsHandler.inter_thread_store.put(session_token+host, new_session); // store session context by session token
        }

        // Close connections -- Authentication etablished and context in memory
        out__.close();
    }






    // *****************************************************************
    // ** Request handling branch
    // *****************************************************************
    // *************************************************************************
    // Perform user file request (branch of if statement)
    private void get_request(BufferedReader in, String host, StringTokenizer st) throws IOException {
        String line1 = null;

        // This branch services requests for BAM file data. This branch is
        // only ever executed for authenticated clients, as indicated by a
        // valid session token from the correct host/IP.
        // BAM file data is accessed using SAMTools/Picard functionality, and sent
        // back to the client in plaintext format, over SSL an connection

        // ---- validate ongoing session --------------------------------------- start
        String filerequest = st.nextToken().substring(1);
        String session_token = st.nextToken();

        if (!session_token.contains("HTTP")) {
            String key = session_token + host;
            if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> " + session_token + host); // DEBUG

            LiveStruct this_session;
            if (HttpsHandler.inter_thread_store.containsKey(key)) { // Existing valid session
                if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> "+key+" CONTAINED IN HASH! AUTHENTICATION SUCCESS"); // DEBUG
                this_session = HttpsHandler.inter_thread_store.get(key);
            } else { // Session key has not been established, or something else went wrong!
                return;
            }
        // ---- validate ongoing session --------------------------------------- end

            // Handle request here
            // Read range from request; determine file location from database;
            // then access file locally, decrypt, pass data on to answer this request!
            String range_request = null;
            while ( !(line1 = in.readLine()).equals("") && line1 != null) {
                if (line1 != null && line1.contains("Range")) {
                    range_request = line1;
                }
            }

            // *****************************************************************
            // *** Data Request Branch - send requested bytes back              ******************************************
            // *****************************************************************
            if (range_request != null && range_request.contains("Range")) { // Actual Data Request
                if (this.verbose) System.out.println("DATA_REQUEST--> " + range_request); // DEBUG

                // ...perform user query
                // ...byte range back - no further processing here!
                SeekableCipherStream_256 stream = this_session.the_stream;
                long offset = Long.parseLong(range_request.substring(range_request.indexOf("=")+1, range_request.indexOf("-")));
                long length = Integer.parseInt(range_request.substring(range_request.indexOf("-")+1)) - offset + 1;
                int int_length = (int)length;
                byte[] read_bytes = new byte[int_length];
                stream.seek(offset);
                stream.read(read_bytes); // Execute user query on local and private BAM file
                OutputStream out = connectionsocket.getOutputStream();
                DataOutputStream dos = new DataOutputStream(out);
                int len = read_bytes.length;
                dos.writeInt(len); // Send length of sent data first, to enable easier read
                if (len > 0) {
                    dos.write(read_bytes, 0, len);
                }
                dos.flush();
                dos.close();
                out = null;


            // *****************************************************************
            // *** Initial File Request - return file length plus index file    ******************************************
            // *****************************************************************
            } else { // Initial file request: return its length
                DataOutputStream out = new DataOutputStream(connectionsocket.getOutputStream());
                //PrintStream out__ = new PrintStream(connectionsocket.getOutputStream());

                BAM_Entry retrieved = (BAM_Entry)this_session.user_files.get(filerequest);

                // The entry may point to a URL or a file at this point. Act accordingly:
                File indexFile = null;
                SeekableCipherStream_256 y1 = null;
                if (retrieved.BAI_url.toLowerCase().contains("http")) { // it's a URL
                    URL indexURL = new URL(retrieved.BAI_url);
                    InputStream indexFileStream = indexURL.openStream();
                    indexFile = File.createTempFile("bai", null);
                    indexFile.deleteOnExit(); // necessary?
                    FileOutputStream indexFOS = new FileOutputStream(indexFile);
                    IOUtils.copy(indexFileStream, indexFOS);
                    indexFOS.close();
                    retrieved.BAI_path = indexFile.getCanonicalPath();

                    URL connect_URL = new URL(retrieved.BAM_url);
                    this_session.BAM_url = connect_URL;
                    this_session.BAI_file = null;
                } else { // treat it as a file within reach of the server
                    retrieved.BAI_path = retrieved.BAI_url;
                    indexFile = new File(retrieved.BAI_path);
                    this_session.BAM_url = null;
                    this_session.BAI_file = new File(retrieved.BAM_url);
                }

                // Connect to the file/source once to get content length
                if (retrieved.BAM_url.toLowerCase().contains("http")) {
                    //y1 = new SeekableCipherStream(new SeekableHTTPStream(new URL(retrieved.BAM_url)), 4, retrieved.pass.getBytes());
                    y1 = new SeekableCipherStream_256(new SeekableHTTPStream(new URL(retrieved.BAM_url)), retrieved.pass.toCharArray(), 4);
                } else {
                    //y1 = new SeekableCipherStream(new SeekableFileStream(new File(retrieved.BAM_url)), 4, retrieved.pass.getBytes());
                    y1 = new SeekableCipherStream_256(new SeekableFileStream(new File(retrieved.BAM_url)), retrieved.pass.toCharArray(), 4);
                }
                StringBuilder buf = new StringBuilder();
                buf.append("Content-Length: ").append(y1.length()).append("\n"); // length of the actual file opened
                this_session.the_stream = y1;
                //y1.close();

                // Send content length back to user's browser
                out.writeBytes(buf.toString());
                sendFile(indexFile, out); // Now uses bytes directly over socket connection
                out.flush();
                out.close();

                // Update LiveData structure: bai file name/location
                this_session.BAI_path = indexFile.getCanonicalPath();
                this_session.BAI_file = indexFile;

                inter_thread_store.update(session_token, this_session); // ?? necessary ??
            }
        }
    }

    // Helper funcrtions -------------------------------------------------------

    private String getString(byte[] input) {
        String result = "";

        for (int i=0; i<input.length; i++)
            result += (char)input[i];

        return result;
    }

    private void sendFile(File targ, DataOutputStream ps) throws IOException {
        byte[] buf = new byte[1024];

        InputStream is = null;
        is = new FileInputStream(targ.getAbsolutePath());

        try {
            int n;
            while ((n = is.read(buf)) > 0) {
                ps.write(buf, 0, n);
            }
        } finally {
            is.close();
        }
    }

}
