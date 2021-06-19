package decryption;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Scanner;


public class Decryption {


    public static void main(String[] args) throws Exception {

        String[] fileName = new String[3];
        fileName[0] = "keystore.jks";
        fileName[1] = "EncryptedFile";
        fileName[2] = "DecryptedFile";

        // generate a public/private key pair
        KeyPair pair = getKeyPairFromKeyStore(fileName[0]);

        //read encryptedfile
        String encryptedText = readEncryptedFile(fileName[1]);

        // Now decrypt it
        Decrypt decrypt = new Decrypt();
        String decipheredMessage = decrypt.decrypt(encryptedText, pair.getPrivate());
        System.out.println(decipheredMessage);

        //write decrypted text to the file
        writeTextFile(fileName[2], decipheredMessage);

        // Let's sign our message
        String signature = sign("foobar", pair.getPrivate());

        // Let's check the signature
        boolean isCorrect = verify("foobar", signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
    }

    public static KeyPair getKeyPairFromKeyStore(String fileName) throws Exception {
        // Generated with:
        // keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg
        // RSA -keystore keystore.jks

        InputStream ins = Decryption.class.getResourceAsStream(fileName);

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

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    private static String readEncryptedFile(String encryptedFile) {
        String cipherText = "";
        File file = new File(encryptedFile);
        Scanner scanner = null;
        try {
            scanner = new Scanner(file);
        } catch (FileNotFoundException s) {
            s.printStackTrace();
            System.out.println("Please try again");
        }

        while (scanner.hasNextLine()) {
            cipherText = scanner.nextLine();
        }

        return cipherText;

    }

    private static void writeTextFile(String decryptedFile, String decipheredMessage) {
         try {
             try (FileWriter fileWriter = new FileWriter(decryptedFile)) {
                 fileWriter.write(decipheredMessage);
             }
        } catch (IOException e) {
        }
    }

}
