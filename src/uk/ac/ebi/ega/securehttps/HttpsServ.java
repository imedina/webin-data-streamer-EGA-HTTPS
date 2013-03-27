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

import java.io.Console;
import java.io.InputStream;
import java.security.InvalidParameterException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ac.ebi.ega.cipher.Glue;
import uk.ac.ebi.embl.ena.dbcomponents.EnaDBComponents;
import uk.ac.ebi.embl.ena.dbcomponents.EnaDBComponents.type;
import uk.ac.ebi.embl.ena.dbcomponents.StringEncrypter;
import uk.ac.ebi.embl.ena.dbcomponents.StringEncrypter.EncryptionException;

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
    private int listening_port;
    private boolean verbose; // DEBUG
    private LiveData inter_thread_store;
    private ExecutorService threadPool;
    private Cipher runtime_encipher, runtime_decipher;
    private EnaDBComponents cpd, pwd;
    
    private String ut, ft, pt; // database table names

    /**
     * @param args the command line arguments
     *              Port - port number for HTTPS requests (defaults to 4..)
     *              Port - port number for FTP(S) requests (defaults to 4..)
     */
    public static void main(String[] args) throws PropertyVetoException {
        String USAGE = "USAGE: java Server [CONFIG_FILE] [optional: password]\n";

        if (args.length != 2 && args.length != 1 && args.length != 5) {
                System.err.print( USAGE );
                throw new InvalidParameterException();                    
        }

        String db_username = "", db_password = "", db_port = "", db = "";
        String pw_db_username = "", pw_db_password = "", pw_db_port = "", pw_db = "";
        boolean test = false;
        if (args.length == 2) { 
            String resource = "/prop.properties";
            if (args[0].contains("config_test")) {
                test = true;
                resource = "/prop_test.properties";
            }
            
            try {
                Properties properties = new Properties();
                //InputStream in = HttpsServ.class.getResourceAsStream("/prop.properties");
                InputStream in = HttpsServ.class.getResourceAsStream(resource);
                properties.load(in);
                
                String db_ = properties.getProperty("database").toString();
                String un_ = properties.getProperty("username").toString();
                String pw_ = properties.getProperty("password").toString();
                String pt_ = properties.getProperty("port").toString();

                String pw_db_ = properties.getProperty("pw_database").toString();
                String pw_un_ = properties.getProperty("pw_username").toString();
                String pw_pw_ = properties.getProperty("pw_password").toString();
                String pw_pt_ = properties.getProperty("pw_port").toString();

                StringEncrypter encrypter = null;
                try {
                    encrypter = new StringEncrypter( StringEncrypter.DESEDE_ENCRYPTION_SCHEME, args[1] );
                    db = encrypter.decrypt(db_);
                    db_username = encrypter.decrypt(un_);
                    db_password = encrypter.decrypt(pw_);
                    db_port = encrypter.decrypt(pt_);
                    
                    pw_db = encrypter.decrypt(pw_db_);
                    pw_db_username = encrypter.decrypt(pw_un_);
                    pw_db_password = encrypter.decrypt(pw_pw_);
                    pw_db_port = encrypter.decrypt(pw_pt_);

                } catch (EncryptionException ex) {
                    java.util.logging.Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
                }                    
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(HttpsServ.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if (args.length == 1) {
            Console c = System.console();
            db = c.readLine("Enter DB: ");
            db_username = c.readLine("Enter DB Username: ");
            db_password = c.readLine("Enter DB Password: ");
            db_port = c.readLine("Enter DB Port: ");                    
            
            pw_db = c.readLine("Enter PW DB: ");
            pw_db_username = c.readLine("Enter PW DB Username: ");
            pw_db_password = c.readLine("Enter PW DB Password: ");
            pw_db_port = c.readLine("Enter PW DB Port: ");                    
        } else if (args.length == 5) {
            db = args[1];
            db_username = args[2];
            db_password = args[3];
            db_port = args[4];
            
            pw_db = args[5];
            pw_db_username = args[6];
            pw_db_password = args[7];
            pw_db_port = args[8];
        }
        
        // Get port numbers; if args missing, use default values (80 HTTP, 443 HTTPS)
        int https_port = 8443; // (989 FTPS Data, 990 FTPS Control; 20 FTP Data, 21 FTP Control)
        boolean verbose = true;

        // New addition: Read config file information
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        //Using factory get an instance of document builder
        String  server_port = "", db_path = "", pw_db_path = "", ut_query = "", ft_query = "", flush = "", pw_query = "";
        DocumentBuilder dbb = null;
        try {
            dbb = dbf.newDocumentBuilder();
            //parse using builder to get DOM representation of the XML file
            Document dom = dbb.parse(args[0]); // name of the config file
            dom.getDocumentElement().normalize();

            NodeList nList = dom.getElementsByTagName("Database");
            for (int temp = 0; temp < nList.getLength(); temp++) {

               Node nNode = nList.item(temp);	    
               if (nNode.getNodeType() == Node.ELEMENT_NODE) {

                  Element eElement = (Element) nNode;                          
                  server_port = getTagValue("ServerPort",eElement);
                  if (server_port.matches("[0-9]+")) https_port = Integer.parseInt(server_port); // actually use specified port
                  db_path = getTagValue("DBPath",eElement);
                  pw_db_path = getTagValue("PWDBPath",eElement);
                  ut_query = getTagValue("UserSQL",eElement);
                  ft_query = getTagValue("FileSQL",eElement);                          
                  pw_query = getTagValue("PwSQL", eElement);
               }

               System.out.println("Config Read.");
            }
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
                                    db_username, 
                                    pw_db_username, 
                                    db_password, 
                                    pw_db_password, 
                                    db_port, 
                                    pw_db_port, 
                                    ut_query, 
                                    ft_query, 
                                    pw_query,
                                    db,
                                    pw_db);
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
                    String DB_username, 
                    String PW_DB_username, 
                    String DB_password, 
                    String PW_DB_password, 
                    String DB_port, 
                    String PW_DB_port, 
                    String ut_, 
                    String ft_, 
                    String pw_, 
                    String DB,
                    String PW_DB) throws PropertyVetoException {
        this.listening_port = listening_port;
        this.verbose = verbose;
        this.ut = ut_;
        this.ft = ft_;
        this.pt = pw_;
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

        // Very new: utilize ENA DB Components instead of ComboPooledDataSources
        int db_port = Integer.parseInt(DB_port);
        this.cpd = new EnaDBComponents(type.MySQL, DB_path, db_port, DB, DB_username, DB_password);
        int pw_db_port = Integer.parseInt(DB_port);
        this.pwd = new EnaDBComponents(type.MySQL, PW_DB_path, pw_db_port, PW_DB, PW_DB_username, PW_DB_password);
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
                this.threadPool.execute(new HttpsHandler_Alternative(connectionsocket, this.verbose, this.inter_thread_store, this, this.ut, this.ft, this.pt));
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

    Connection getAConn() throws SQLException {
        //return this.cpds.getConnection();
        return this.cpd.getAConnection();
    }
    public Connection getAPWConn() throws SQLException {
        //return this.pwds.getConnection();
        return this.pwd.getAConnection();
    }
}
