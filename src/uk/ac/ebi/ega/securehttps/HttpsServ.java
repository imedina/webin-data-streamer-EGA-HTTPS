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

import java.beans.PropertyVetoException;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.security.InvalidParameterException;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ac.ebi.ega.cipher.Glue;
import uk.ac.ebi.embl.ena.dbcomponents.StringEncrypter;
import uk.ac.ebi.embl.ena.dbcomponents.StringEncrypter.EncryptionException;
import uk.ac.ebi.embl.ena.infinicache.memCache;

/**
 *
 * @author asenf
 * 
 * This is the listener class. Each HTTP(S) connection request is accepted here and
 * then passed on to a child thread for handling. All worker threads originate here,
 * so this is the place where session information is maintained.
 *
 * LiveData contains all information required to maintain user sessions, allowing users
 * to authenticate once and then work without continuous password requests. Sessions
 * are encrypted using session-specific random keys and are subject to timeouts.
 * Sessions are also tied to IP addresses, and write cookies to enable load balancers
 * to properly treat user requests. Session-specific data is generated and handled
 * by the worker threads.
 *
 */
public class HttpsServ implements Runnable {
    private final int listening_port;
    private final boolean verbose; // DEBUG
    private final LiveData inter_thread_store;
    private final ExecutorService threadPool;
    private Cipher runtime_encipher, runtime_decipher;
    
    private final memCache the_cache;
    
    /**
     * @param args the command line arguments
     *              Port - port number for HTTPS requests (defaults to 4..)
     *              Port - port number for FTP(S) requests (defaults to 4..)
     * @throws java.beans.PropertyVetoException
     */
    public static void main(String[] args) throws PropertyVetoException {
        System.setProperty("java.net.preferIPv4Stack" , "true");
        String USAGE = "USAGE: java Server [CONFIG_FILE] [optional: password]\n";

        String version = "0.0", key = "";

        String versionfile = "clientversion.txt"; // latest version of the client
        File vf = new File(versionfile);
        try {
            BufferedReader br = new BufferedReader(new FileReader(vf));
            version = br.readLine();
            br.close();
        } catch(Throwable t) {
            ; // If no version file exists, don't use the feature
        }
        String keyfile = "start.key"; // key for properties
        File kf = new File(keyfile);
        try {
            BufferedReader br = new BufferedReader(new FileReader(kf));
            key = br.readLine();
            br.close();
        } catch(Throwable t) {
            if (args.length >= 2)
                key = args[1];
        }
                
        if (args.length != 2 && args.length != 1) {
                System.err.print( USAGE );
                throw new InvalidParameterException();                    
        }

        String  db_username = "", db_password = "", server_port = "", 
                db_path = "", db = "", db_hash = "", db_port = "", 
                pw_db_path = "", pw_db = "", pw_db_port = "";
        boolean test = false;
        if (args.length == 1) { 
            String resource = "/prop.properties";
            if (args[0].contains("config_test")) {
                test = true;
                resource = "/prop_test.properties";
            }

            try {
                Properties properties = new Properties();
                //InputStream in = Server.class.getResourceAsStream("/prop.properties");
                InputStream in = HttpsServ.class.getResourceAsStream(resource);
                properties.load(in);

                String un_ = properties.getProperty("username").toString();
                String pw_ = properties.getProperty("password").toString();

                StringEncrypter encrypter = null;
                try {
                    //encrypter = new StringEncrypter( StringEncrypter.DESEDE_ENCRYPTION_SCHEME, args[1] );
                    encrypter = new StringEncrypter( StringEncrypter.DESEDE_ENCRYPTION_SCHEME, key );

                    db_username = encrypter.decrypt(un_);
                    db_password = encrypter.decrypt(pw_);

                } catch (EncryptionException ex) {
                    java.util.logging.Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
                }                    
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        // Get port numbers; if args missing, use default values (80 HTTP, 443 HTTPS)
        int https_port = 8443; // (989 FTPS Data, 990 FTPS Control; 20 FTP Data, 21 FTP Control)
        boolean verbose = true;

        // New addition: Read config file information
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        DocumentBuilder dbb = null;
        try {
            dbb = dbf.newDocumentBuilder();
            //parse using builder to get DOM representation of the XML file
            Document dom = dbb.parse(args[0]); // name of the config file
            dom.getDocumentElement().normalize();

            //String  server_port = "", db_path = "", pw_db_path = "", ut_query = "", ft_query = "", flush = "", pw_query = "";
            String log_file = "";
            int bs = 0;
            NodeList nList = dom.getElementsByTagName("Database");
            for (int temp = 0; temp < nList.getLength(); temp++) {

               Node nNode = nList.item(temp);	    
               if (nNode.getNodeType() == Node.ELEMENT_NODE) {

                  Element eElement = (Element) nNode;                          
                  server_port = getTagValue("ServerPort",eElement);
                  if (server_port.matches("[0-9]+")) https_port = Integer.parseInt(server_port); // actually use specified port

                  db_path = getTagValue("DBPath",eElement);
                  db = getTagValue("DB",eElement);
                  db_hash = getTagValue("DBH",eElement);
                  db_port = getTagValue("DBPort",eElement);

                  pw_db_path = getTagValue("PWDBPath",eElement);
                  pw_db = getTagValue("PWDB",eElement);
                  pw_db_port = getTagValue("PWDBPort",eElement);
               }
            }
            nList = dom.getElementsByTagName("Transfer");
            for (int temp = 0; temp < nList.getLength(); temp++) {

               Node nNode = nList.item(temp);	    
               if (nNode.getNodeType() == Node.ELEMENT_NODE) {

                  Element eElement = (Element) nNode;                          
                    try {
                      log_file = getTagValue("LogFileName",eElement);
                    } catch (NullPointerException ex) {log_file=null;} // in case this line is missing
                }                       
            }

            System.out.println("Config Read.");
        } catch (ParserConfigurationException ex) {
            java.util.logging.Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch( Exception e ) {
            System.err.println( "FATAL ERROR: ABORTING Secure EGA HTTPS Server!!!" );
            e.printStackTrace();
        }
        
        /* Start a new thread:
         *      A thread listens for HTTPS requests on the specified port and
         *          spawns a new thread for each connection request. Each child
         *          thread will be a session with its own session token and password
         */

        // HTTPS Requests
        HttpsServ web_server;
        //web_server = new HttpsServ(https_port, verbose, db_path, args[0], args[1], args[2], ut_query, ft_query);
        web_server = new HttpsServ(https_port, 
                                    verbose, 
                                    db_path, 
                                    pw_db_path, 
                                    db_path, 
                                    db_username, 
                                    db_username, 
                                    db_username, 
                                    db_password, 
                                    db_password, 
                                    db_password, 
                                    db_port, 
                                    pw_db_port, 
                                    db_port, 
                                    db,
                                    pw_db,
                                    db_hash,
                                    key);
        //web_server.start();
        new Thread( web_server ).start();
        System.out.println("HTTPS Server started on port " + https_port);

    }
    private static String getTagValue(String sTag, Element eElement){
        NodeList nlList= eElement.getElementsByTagName(sTag).item(0).getChildNodes();
        Node nValue = (Node) nlList.item(0); 

        return nValue.getNodeValue();    
    }   
    
    // Constructor: define port number for requests
    public HttpsServ(int listening_port, 
                    boolean verbose, 
                    String DB_path, 
                    String PW_DB_path, 
                    String DR_DB_path, 
                    String DB_username, 
                    String PW_DB_username, 
                    String DR_DB_username, 
                    String DB_password, 
                    String PW_DB_password, 
                    String DR_DB_password, 
                    String DB_port, 
                    String PW_DB_port, 
                    String DR_DB_port, 
                    String DB,
                    String PW_DB,
                    String DR_DB,
                    String k) throws PropertyVetoException {
        this.listening_port = listening_port;
        this.verbose = verbose;
        //this.threadPool = Executors.newFixedThreadPool(10);
        this.threadPool = Executors.newCachedThreadPool(); // See how that worls with memory requirements
        this.inter_thread_store = LiveData.LiveData(); // Generate an instance of the singleton LiveData

        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5"); // get the hash algorithm
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] key = md5.digest(Glue.getInstance().GenerateRandomString(10, 20, 2, 2, 2, 2));// hash a random pwd to make a 128bit key
        SecretKeySpec skey = new SecretKeySpec(key,"AES"); // create a key suitable for AES
        IvParameterSpec ivSpec = new IvParameterSpec(md5.digest(key)); // create an init vector (based on the key, hashed again)
        try {
            this.runtime_encipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            this.runtime_decipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            this.runtime_encipher.init(Cipher.ENCRYPT_MODE, skey,ivSpec);
            this.runtime_decipher.init(Cipher.DECRYPT_MODE, skey,ivSpec);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        this.the_cache = new memCache(DB_path, 
                                      DB_port, 
                                      DB_username, 
                                      DB_password,  
                                      DB,
                                      PW_DB_path, 
                                      PW_DB_port, 
                                      PW_DB_username, 
                                      PW_DB_password,   
                                      PW_DB,
                                      null, 
                                      null, 
                                      null, 
                                      null, 
                                      null,
                                      DR_DB_path, 
                                      DR_DB_port, 
                                      DR_DB_username, 
                                      DR_DB_password, 
                                      DR_DB,
                                      k); // Key used by external SQL source for encryption
    }

    //this is a overridden method from the Thread class we extended from
    @Override
    public void run() {
        try {

            SSLContext sslContext = SSLContext.getDefault(); // getOptions().getSslContext();

            KeyManagerFactory kmf;
            KeyStore ks = null;

            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(new FileInputStream("keystore"), "secret".toCharArray());
            kmf = KeyManagerFactory.getInstance("SunX509");
            sslContext = SSLContext.getInstance("SSL"); // TLS

            kmf.init(ks, "secret".toCharArray());
            sslContext.init(kmf.getKeyManagers(), null, null);

            SSLServerSocketFactory factory = (SSLServerSocketFactory) sslContext.getServerSocketFactory();
            SSLServerSocket sslServerSocket = (SSLServerSocket) factory.createServerSocket(this.listening_port);
            sslServerSocket.setNeedClientAuth(false);

            String[] cipherSuites = {"SSL_RSA_WITH_RC4_128_MD5","SSL_RSA_WITH_RC4_128_SHA",
                    "TLS_RSA_WITH_AES_128_CBC_SHA","TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA","SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA","SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA"};

            sslServerSocket.setEnabledCipherSuites(cipherSuites);
            ServerSocket serversocket = sslServerSocket;

            // Insecure version:
            //ServerSocket serversocket = new ServerSocket(this.listening_port); // insecure

            while(true){
                Socket connectionsocket = null;
                try {
                    connectionsocket = serversocket.accept();
                } catch (IOException e) {
                    throw new RuntimeException("Error accepting client connection", e);
                }
                this.threadPool.execute(new HttpsHandler_Alternative(connectionsocket, this.verbose, this.inter_thread_store, this));
            }

        } catch (IOException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        }  catch (KeyManagementException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public memCache getCache() {
        return this.the_cache;
    }
}
