package encryption;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Encryption {

    public static void main(String[] args) throws Exception {

        String[] fileName = new String[3];
        fileName[0] = "keystore.jks";
        fileName[1] = "E:/HND/SS/CW/Encryption/fileToEncrypt.txt";
        fileName[2] = "EncryptedFile";

        //generate public and private key pair
        KeyPair pair = getKeyPairFromKeyStore(fileName[0]);

        // Encryption the message
        Encrypt encrypt = new Encrypt();

        // read text file
        String message = readTextFile(fileName[1]);
        System.out.println("Original message: " + message);

        //encrypt it
        String cipherText = encrypt.encrypt(message, pair.getPublic());
        System.out.println(cipherText);

        //write encrypted text to the file
        writeTextFile(fileName[2], cipherText);

    }

    public static KeyPair getKeyPairFromKeyStore(String keyFile) throws Exception {
        // Generated with:
        // keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg
        // RSA -keystore keystore.jks

        InputStream ins = Encryption.class.getResourceAsStream(keyFile);

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray()); // Keystore password
        KeyStore.PasswordProtection keyPassword
                = // Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    private static String readTextFile(String textFile){
        String data = null;
        try {
            data = new String(Files.readAllBytes(Paths.get(textFile)));
        } catch (IOException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        return data;

    }

    private static void writeTextFile(String encryptedFile, String cipherText) {
        try {
            try (FileWriter fileWriter = new FileWriter(encryptedFile)) {
                fileWriter.write(cipherText);
            }
        } catch (IOException e) {
        }
    }

  

}
