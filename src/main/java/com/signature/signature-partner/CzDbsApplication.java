package com.cashlez.czdbs;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CzDbsApplication {
    private final static String PRIVATE_KEY =
            "-----BEGIN RSA PRIVATE KEY-----\n"
                    + "MIIEpQIBAAKCAQEA0WtqLDs2GEOdJkp2bWilvzgcfMQJS1A0GrFbpLBnjmdJ/ene\n"
                    + "AQXbJGT+9wgDjvdGvnLqWuIfeyMrUgArAuxJZ03an0trfJ5U+31TUgG4NnMlvPTL\n"
                    + "yETCk2eWrMiDo/Q+VesQLae/Ws67CUWqmSts4XcAgujiUcczW2JSl4dVkw2DvQQJ\n"
                    + "irFwlnpFE7mCqtPlMOiv/Yr2i05U+8LTD6zwQhsz9VHuapU686HnC/70CMjgrA07\n"
                    + "gL1GOI792QaATK5/zqy6rCQ5Fr+OMxySGGTIhm00TrQ9HhUy1X0HCFoAya/3LCsM\n"
                    + "cTXLKZYnkFFFrd6zYuvHjs7e/YwAPxhBTW27tQIDAQABAoIBAQCnRL6HGbw5YTgS\n"
                    + "L4OsG9vXgf/u/73Us/kKIQNr5aKxMXr+HmA+POkuhqTHt1TwSj3tPGhHszkl549g\n"
                    + "bdXs/cIbiynF9j2iSezi+tUkOU9j3lEUPgrOqW0ow6Kr23SZ7iokAh7n+IZ1B46I\n"
                    + "92Yt9WuAIsb7yPuMCinRIhWKBoSpcLyPby/IRxOp7U4VA0tnM76kgQ0wXGAzQ+YX\n"
                    + "pQGyB3RPlgSf9gogjhX7ad23bKVBJmrp5Y8r8q5YcmGKRkHVMg/yIAjXcgSv2KMY\n"
                    + "JU7Oda+DyTQcAv4xpXkwVrQuijSTTrJZlGg0zaNb36y6fKON1OOD4fh4PmSGKEAy\n"
                    + "a8OLMbvBAoGBAP2jl0aGUXQaLlYAP+2sPQM73tLOWPGWblorXv2cVho53gjgK+ww\n"
                    + "1b6QMqrI2+Mh74RRjwq9YL4XSgyh24XksWUpDAPIts8MP35NK71F/sJsKq/asziS\n"
                    + "JMTgQJ8PEx/Y/IqISU1BehTHHFoFIuSdaqrH1YC6RjboNRapHkyWmhRJAoGBANNe\n"
                    + "c3w261jm59MXQ2SQ45iqmKZLvRp8hzM5RFyNKlceIJtFiD1UZn69AqPx8UltdTFG\n"
                    + "rxcypDS9pUGr4Gqgixmg+1xT9tZvfjz8MNMA9Dsg28mM67atKEZ+A9b0F0xPOAww\n"
                    + "CndqtD+qFnag1u0oAQBqT7MbCpWnM2pKrA9D3RQNAoGBAOKBWzDR9p+2WbbXlj+L\n"
                    + "1xiyOLUNLYThkD7aCIR3PrVBBDXs64yLt/XsFDNMGIHn5lvF8fXnVSOs7KYHTWFu\n"
                    + "77SlSWN/tTGFgJYsGGl4vp+ltSFCL1bPvCJNGahx7+Q7BJw6RSvG010GyxzhBV4f\n"
                    + "7ggBWXsR3m5eRDquYK6It6RxAoGAOEAdmcP/0/P3Y/z/6WaJu1pDL5ZeaAsV6/Lk\n"
                    + "l4DV8MNKyCez/yZT9IyWhEzh+rmPg6Kc/B51Brgln5l/KsE444QtAMAzo5OeU9qF\n"
                    + "n9HULVwsQbIoFMB2RHRKz0y8WomGj+/FCUyzVXINclqReCG6SoMAXNjoczVBAJuI\n"
                    + "uLNFxY0CgYEA8n3YtgK8e7xw3XQBiavRtkYPR4XzaRuYgUUXBYXFoJOndYHIPTKg\n"
                    + "9B4EJf3eK9hZwfQOOHWT1ZbiKmUthETbaxb7B31Oj1lfHug9AUjCSKp5siANPfEb\n"
                    + "4hJNGuXhzRrkuMwn913PgjUxBtNXxWPe2s4LG4Z8uqX06MBW4aE5alU=\n"
                    +        "-----END RSA PRIVATE KEY-----";
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PrivateKey retrievedPrivateKey = getPrivateKey(PRIVATE_KEY);

//        System.out.println(retrievedPrivateKey + "private Key");
//
//        File file = new File("/home/rifaimartin/Documents/public.pem");
//
//        if (!file.exists()) {
//            System.out.println("kagak ada");
//        }

//        PrivateKey privateK = getPrivateKey("/home/rifaimartin/Documents/private_unencrypted.pem");

        PublicKey publicK = getPublicKey("/home/rifaimartin/Documents/public.pem");

        String msg = "HAJAR OAKWOAKWOKAWOKWA  ";

        String signSS = Sign(retrievedPrivateKey, msg);

        System.out.println(signSS + "SIGNATURE TOKPED");


        System.out.println(Verify( publicK, signSS, msg  ));
    }

    public static PrivateKey getPrivateKey(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        // Read in the key into a String
//        StringBuilder pkcs8Lines = new StringBuilder();
//        BufferedReader rdr = new BufferedReader(new FileReader(filename));
//        String line;
//        while ((line = rdr.readLine()) != null) {
//            pkcs8Lines.append(line);
//        }
        // Remove the "BEGIN" and "END" lines, as well as any whitespace
        String pkcs8Pem = filename;
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END RSA PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");
        // Base64 decode the result
        System.out.println(pkcs8Pem + "check data");

        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);
        // extract the private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        System.out.println(privKey + "encoded tokped");
        return privKey;
    }

    public static String Sign(PrivateKey privateKey, String msg) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            byte[] message = msg.getBytes();
            signature.update(message);
            byte[] sigBytes = signature.sign();
            byte[] sig64 = Base64.getEncoder().encode(sigBytes);
            return new String(sig64);
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
        return "";
    }

    public static boolean Verify(PublicKey publicKey, String signature, String msg) {
        try {
            byte[] sigBytes = Base64.getDecoder().decode(signature.getBytes());
            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decSig = cipher.doFinal(sigBytes);
            ASN1InputStream aIn = new ASN1InputStream(decSig);
            ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
            MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");
            hash.update(msg.getBytes());
            ASN1OctetString sigHash = (ASN1OctetString) seq.getObjectAt(1);
            return MessageDigest.isEqual(hash.digest(), sigHash.getOctets());
        } catch (Exception ex) {
        }
        return false;
    }

    public static PublicKey getPublicKey(String fileName) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            File file = new File(fileName);
            try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
                PemObject pemObject = pemReader.readPemObject();
                byte[] content = pemObject.getContent();
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
                PublicKey publicKey = factory.generatePublic(pubKeySpec);
                return publicKey;
            } catch (Exception exx) {
                System.out.println(exx.toString());
            }
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
        return null;
    }




}
