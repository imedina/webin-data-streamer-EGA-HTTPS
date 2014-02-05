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

import java.util.ArrayList;
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
import net.sf.samtools.seekablestream.SeekableFileStream;
import net.sf.samtools.seekablestream.SeekableHTTPStream;
import net.sf.samtools.seekablestream.SeekableStream;

import org.apache.commons.io.IOUtils;
import uk.ac.ebi.ega.cipher.Glue;
import uk.ac.ebi.ega.cipher.SeekableCipherStream_256;
import uk.ac.ebi.embl.ena.fileaccess.ena_db_file_ext_thread;
import uk.ac.ebi.embl.ena.fileaccess.file_data;

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
public class HttpsHandler_Alternative extends Thread {
    // Should be the same across multiple threads - it's the port defined at startup
    private final Socket connectionsocket;
    private final boolean verbose; // DEBUG ONLY
    private static LiveData inter_thread_store;
    
    private final HttpsServ server;
    
    private String user_id;

    // Constructor - receive an active socket connection once a request has been made
    public HttpsHandler_Alternative(Socket connectionsocket, boolean verbose, LiveData inter_thread_store, HttpsServ serv) {
        this.connectionsocket = connectionsocket; // accepted connection
        this.verbose = verbose;
        HttpsHandler_Alternative.inter_thread_store = inter_thread_store; // authentication information
        this.server = serv;
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
                get_request(in, host, st); // request file (portion of..; BAM or BAI file)

            } else { // Invalid Request
                // If neither GET, POST, LIST, or LDS were sent, this server will not respond.
                // Options include logging, doing nothing, sending error messages
                if (this.verbose) {
                    System.out.println("ILLEGAL REQUEST");
                    System.out.println("Request from " + host + " received that does not conform to specifications!");
                }
            }
            in.close();
            // *****************************************************************
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                connectionsocket.close();
            } catch (IOException ex) {
                Logger.getLogger(HttpsHandler_Alternative.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    // *************************************************************************
    // Perform user authentication: connect to database and query user name
    private ArrayList dataValidation(String username, String pw) {
        ArrayList result = new ArrayList();

        String user_id = this.server.getCache().checkLoginCachedDrupal(username, pw);
        result.add(user_id);
        
        if (user_id != null && !user_id.isEmpty()) {
            this.user_id = user_id;
        }        
        
        return result;
    }
    private String get_pass_for_file(String filename) {
        String pw = "";

        pw = this.server.getCache().get_pass_for_file(filename);

        return pw;
    }




    // *****************************************************************
    // ** Authentication branch                                         
    // *****************************************************************
    // *************************************************************************
    // Perform user authentication request (branch of if statement)
    private void post_request(BufferedReader in, String host) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        //GZIPOutputStream out__ = new GZIPOutputStream(connectionsocket.getOutputStream());
        OutputStream out__ = connectionsocket.getOutputStream();

        String line1 = null;

        // This branch answers to POST connection requests - it expects a username/password
        // and established that the requesting client has indeed access. Then a session token
        // is generated and given to the client to indicate successful authentication for
        // future requests.
        while ((!(line1 = in.readLine()).equalsIgnoreCase(""))) {
            if (this.verbose) System.out.println("--> " + line1);
        }
        line1 = in.readLine();
        if (line1 != null) {

            String username = line1.substring(line1.indexOf("=")+1, line1.indexOf(":"));
            String pw = line1.substring(line1.lastIndexOf("=")+1, line1.length());
            byte[] password = line1.substring(line1.lastIndexOf("=")+1, line1.length()).getBytes();
            String e = null;
            try {
                e = line1.substring(line1.lastIndexOf("=")+1, line1.length());
                if (e.equals(pw)) e = null;
            } catch (Throwable t) {;}
            
            // Access Database - Validate User Credentials
            ArrayList valResult = dataValidation(username, pw), userResponse = null;

            // Send Server Response back to client
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            String session_token = String.valueOf(sr.nextGaussian()+"X"+sr.nextDouble()+"X"+sr.nextGaussian()+".bam"); // For SAMFileReader Interaction
            StringBuilder sb = new StringBuilder(); // TODO: potentially... proper header Pfft. Java 7_45 requires it!
            sb.append("HTTP/1.0 200 OK").append("\n").append("\n");
out__.write(sb.toString().getBytes());
//out__.flush();
out__ = new GZIPOutputStream(out__);
sb = new StringBuilder();
            sb.append("Authentication_Success").append(" ").append(session_token).append(" \n").append("\n");

            out__.write(sb.toString().getBytes());
((GZIPOutputStream)out__).finish(); // complete the zlib stream
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
            // No longer store user's files in the session store - use mem cache for that
            //new_session.user_files = user_files; // All user's files and locations
            new_session.username = this.user_id;
//System.out.println("Storing -- " + new_session.username + "  " + this.user_id);

            HttpsHandler_Alternative.inter_thread_store.put(session_token+host, new_session); // store session context by session token
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
        if (filerequest.endsWith("LDS")) {
            lds_request(in, host, st);
            return;
        } else if (filerequest.endsWith("LIST")) {
            list_request(in, host, st);
            return;
        }
        String session_token = st.nextToken();
        boolean index = filerequest.toUpperCase().contains(".BAM.BAI");

        if (!session_token.contains("HTTP")) {
            String key = session_token + host;
            if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> " + session_token + host); // DEBUG

            LiveStruct this_session;
            if (HttpsHandler_Alternative.inter_thread_store.containsKey(key)) { // Existing valid session
                if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> "+key+" CONTAINED IN HASH! AUTHENTICATION SUCCESS"); // DEBUG
                this_session = HttpsHandler_Alternative.inter_thread_store.get(key);
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
                
                // TODO: Cipher for BAM, Plain for BAI
                SeekableStream the_stream = null;
                if (!index)
                    the_stream = this_session.the_stream; // Encrypted BAM file Stream
                else
                    the_stream = this_session.the_index_stream; // Plain Index Stream
                //SeekableCipherStream_256 stream = this_session.the_stream;
                long offset = Long.parseLong(range_request.substring(range_request.indexOf("=")+1, range_request.indexOf("-")));
                long length = Integer.parseInt(range_request.substring(range_request.indexOf("-")+1)) - offset + 1;
                int int_length = (int)length;
                byte[] read_bytes = new byte[int_length];
                the_stream.seek(offset);
                the_stream.read(read_bytes); // Execute user query on local and private BAM file
                //stream.seek(offset);
                //stream.read(read_bytes); // Execute user query on local and private BAM file
                OutputStream out = connectionsocket.getOutputStream();
                out.write("HTTP/1.0 200 OK\n\n".getBytes()); // Java 7 header; after that, unchanged
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

                String f_request = filerequest; // Requested File Name
                if (index) // If the file is an index file - modify file name to get Index from data structure
                    f_request = f_request.substring(0, f_request.toLowerCase().indexOf(".bai")) + ".cip";
                BAM_Entry retrieved = (BAM_Entry)this_session.user_files.get(f_request); // filerequest

                // The entry may point to a URL or a file at this point. Act accordingly:
                File indexFile = null;
                //SeekableCipherStream_256 y1 = null;
                SeekableStream y1 = null;
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
System.out.println(" --> TODO: MUST IMPLEMENT THIS SECTION FULLY");
                } else { // treat it as a file within reach of the server
                    retrieved.BAI_path = retrieved.BAI_url;
                    this_session.BAM_url = null;
                    if (!index) this_session.BAI_file = new File(retrieved.BAM_url);
                }

                // Connect to the file/source once to get content length
                if (!index) { // Treat BAM and BAI files differently
                    if (retrieved.BAM_url.toLowerCase().contains("http")) {
                        y1 = new SeekableCipherStream_256(new SeekableHTTPStream(new URL(retrieved.BAM_url)), retrieved.pass.toCharArray(), 4);
                        // This branch should not actually be used
                    } else {
                        y1 = new SeekableCipherStream_256(new SeekableFileStream(new File(retrieved.BAM_url)), retrieved.pass.toCharArray(), 4);
                    }
                    this_session.the_stream = (SeekableCipherStream_256) y1; // BAM stream
                } else { // It's a BAI file, not a BAM File
                    y1 = new SeekableFileStream(new File(retrieved.BAI_path));
                    this_session.the_index_stream = y1; // BAI stream
                }
                StringBuilder buf = new StringBuilder();
//                buf.append("HTTP/1.0 200 OK").append("\n").append("\n");
//                buf.append("Content-Length: ").append(y1.length()).append("\n"); // length of the actual file opened
                buf.append("HTTP/1.0 200 OK").append("\n");
                buf.append("Content-Length: ").append(y1.length()).append("\n").append("\n"); // length of the actual file opened
                //y1.close();

                // Send content length back to user's browser
                out.writeBytes(buf.toString());
// New: Don't send Index file to client! It will be a stream, just like the BAM file
                //sendFile(indexFile, out); // Now uses bytes directly over socket connection
                out.flush();
                out.close();

                // Update LiveData structure: bai file name/location
                //this_session.BAI_path = indexFile.getCanonicalPath();
                //this_session.BAI_file = indexFile;

                inter_thread_store.update(session_token, this_session); // ?? necessary ??
            }
        }
    }

    // *****************************************************************
    // ** List handling branch
    // *****************************************************************
    // *************************************************************************
    // e.g. LIST _sessiontoken_ [dataset id]
    // List useable, authorized files for authenticated users (used to be part of
    // connection procedure, but no longer due to size/time concerns)
    private void list_request(BufferedReader in, String host, StringTokenizer st) throws IOException {
System.out.println("List Request");
//        GZIPOutputStream out__ = new GZIPOutputStream(connectionsocket.getOutputStream());
        OutputStream out_ = connectionsocket.getOutputStream();
        
        // ---- validate ongoing session --------------------------------------- start
        String session_token = st.nextToken();

        LiveStruct this_session = null;
        if (!session_token.contains("HTTP")) {
            String key = session_token + host;
            if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> " + session_token + host); // DEBUG

            if (HttpsHandler_Alternative.inter_thread_store.containsKey(key)) { // Existing valid session
                if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> "+key+" CONTAINED IN HASH! AUTHENTICATION SUCCESS"); // DEBUG
                this_session = HttpsHandler_Alternative.inter_thread_store.get(key);
                if (this_session == null)
                    return;
            } else { // Session key has not been established, or something else went wrong!
                return;
            }
        // ---- validate ongoing session --------------------------------------- end            
        } else {
            return;
        }

        // ** Handle request here **
        // First, get a list of all applicable files ---------------------------
        String dataset = null;
        if (st.hasMoreTokens())
            dataset = st.nextToken();
        if (dataset.contains("HTTP"))
            dataset = null;
System.out.println("For: " + this_session.username + " " + dataset);
        
        file_data[] list = (dataset==null)?
                this.server.getCache().list(this_session.username):
                this.server.getCache().list(this_session.username, dataset, ena_db_file_ext_thread.id_type.Dataset);
        ArrayList valResult = new ArrayList(); // filename, index_name, password            
        if (list != null) {
            for (int i=0; i<list.length; i++) {
//System.out.println(list[i].file_name.toLowerCase());
                if (list[i].file_name.toLowerCase().endsWith(".bam.cip") ||
                    list[i].file_name.toLowerCase().endsWith(".bam")) {
                    valResult.add(list[i].file_name);
                    valResult.add(list[i].index_name);
                    valResult.add(list[i].enc_pw);
                }
            }
        }
        
        // Second, respond by sending that list --------------------------------
        ArrayList userResponse = new ArrayList();
        for (int i=0; i<valResult.size(); i+=3) { // Artefact of previous code usage
            String bam_url = valResult.get(i).toString();
            if (!bam_url.toLowerCase().endsWith(".gpg")) { // no longer required
                String bai_url = valResult.get(i+1).toString();
                String pass = valResult.get(i+2).toString();
                String filename = bam_url.substring(bam_url.lastIndexOf("/")+1);
                userResponse.add(filename);
            }
        }

        // Build response to user query, and send it
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.0 200 OK").append("\n").append("\n");
out_.write(sb.toString().getBytes());
out_ = new GZIPOutputStream(out_);
sb = new StringBuilder();
        for (int i=0; i<userResponse.size(); i++)
            sb.append(userResponse.get(i).toString()).append("\n");
        out_.write(sb.toString().getBytes());
((GZIPOutputStream)out_).finish(); // complete the zlib stream
        out_.flush();

        // Close connections -- Authentication etablished and context in memory
        out_.close();
    }
    
    // *****************************************************************
    // ** List handling branch
    // *****************************************************************
    // *************************************************************************
    // e.g. LIST _sessiontoken_ [dataset id]
    // List useable, authorized files for authenticated users (used to be part of
    // connection procedure, but no longer due to size/time concerns)
    private void lds_request(BufferedReader in, String host, StringTokenizer st) throws IOException {
        //GZIPOutputStream out__ = new GZIPOutputStream(connectionsocket.getOutputStream());
        OutputStream out_ = connectionsocket.getOutputStream();
        
        // ---- validate ongoing session --------------------------------------- start
        String session_token = st.nextToken();

        LiveStruct this_session = null;
        if (!session_token.contains("HTTP")) {
            String key = session_token + host;
            if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> " + session_token + host); // DEBUG

            if (HttpsHandler_Alternative.inter_thread_store.containsKey(key)) { // Existing valid session
                if (this.verbose) System.out.println("SESSIONTOKEN_HOST--> "+key+" CONTAINED IN HASH! AUTHENTICATION SUCCESS"); // DEBUG
                this_session = HttpsHandler_Alternative.inter_thread_store.get(key);
                if (this_session == null)
                    return;
            } else { // Session key has not been established, or something else went wrong!
                return;
            }
        // ---- validate ongoing session --------------------------------------- end            
        } else {
            return;
        }
        // ** Handle request here **
        // First, get a list of all applicable files ---------------------------
        System.out.println("Getting for ID: " + this_session.username + "  " + this.user_id);
        String[] iDs = this.server.getCache().getIDs(this_session.username, "", ena_db_file_ext_thread.id_type.Dataset);
        
        // Second, respond by sending that list --------------------------------
        // Build response to user query, and send it
        StringBuilder sb = new StringBuilder();
//out_ = new GZIPOutputStream(out_);
        sb.append("HTTP/1.0 200 OK").append("\n").append("\n");
out_.write(sb.toString().getBytes());
out_ = new GZIPOutputStream(out_);
sb = new StringBuilder();
        for (int i=0; i<iDs.length; i++)
            sb.append(iDs[i]).append("\n");
        out_.write(sb.toString().getBytes());
((GZIPOutputStream)out_).finish(); // complete the zlib stream
        out_.flush();

        // Close connections -- Authentication etablished and context in memory
        out_.close();
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
