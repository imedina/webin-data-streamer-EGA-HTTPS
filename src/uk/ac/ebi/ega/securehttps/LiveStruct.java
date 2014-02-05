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

import java.io.File;
import java.net.URL;
import java.util.HashMap;
import javax.crypto.Cipher;
import net.sf.samtools.seekablestream.SeekableStream;
import uk.ac.ebi.ega.cipher.SeekableCipherStream_256;

/**
 *
 * @author asenf
 */
public class LiveStruct {
    public String session_token;
    public String username;
    public byte[] user_password; // may not be a good idea.....
    public Cipher encipher;
    public Cipher decipher;
    public String BAI_path;
    public File BAI_file;
    public URL BAM_url;
    public File BAM_File;
    public HashMap user_files;
    public SeekableCipherStream_256 the_stream;
    public SeekableStream the_index_stream;
}
