package com.isfs.blekey.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.isfs.blekey.ctap.CtapHid;
import com.isfs.blekey.data.Passkey;

import jakarta.xml.bind.DatatypeConverter;

public class FileUtils {

    private static final Logger logger = LoggerFactory.getLogger(FileUtils.class);

    public static byte[] readPEMFile(String fName)  throws IOException {
        StringBuilder sb = null;
        try { // try read file from string
            InputStream inStream = new FileInputStream(fName);
            BufferedReader br = new BufferedReader(new InputStreamReader(inStream));
            sb = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.contains("BEGIN")
                            && (line.contains("KEY") || line.contains("CERTIFICATE"))) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.contains("END")
                            && (line.contains("KEY") || line.contains("CERTIFICATE"))) {
                        inKey = false;
                        break;
                    }
                    sb.append(line);
                }
            }
            br.close();
            inStream.close();
        } catch (IOException ioe) { // if we fail use the literal string
            sb = new StringBuilder(fName);
        }
        byte[] rawKey = DatatypeConverter.parseBase64Binary(sb.toString());
        return rawKey;
    }

    public static List<File> listPasskeys() {
        String fidoHomeStr = System.getenv("FIDO_HOME");
        if (fidoHomeStr == null || fidoHomeStr.isEmpty()) {
            return null;
        }
        List<File> result = new ArrayList<>(); 
        for(File maybePasskey: new File(fidoHomeStr).listFiles()) {
            try {
                if(maybePasskey.isFile() && 
                        maybePasskey.getAbsolutePath().endsWith(".passkey")) {
                    result.add(maybePasskey);
                }
            } catch (Exception e) {
                logger.error("Error decrypting key", e);
            }
        }
        return result;
    }
}
