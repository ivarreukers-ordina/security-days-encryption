package encryption;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class Main {
    // lazy
    private static final String BASE_PATH = "/Users/ivarreukers/Downloads/code-examples-master/spring-boot/hashing/src/encryption";
    //doesn't work for some reason
    private static final String ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    private static final String PLAIN_RSA = "RSA";

    private static final String ME = "ivar";

    public static void main(String args[]) throws Exception {
        Key privateKey = readKeyFromFile(BASE_PATH + "rsa_key.priv", false);
        Key publicKey = readKeyFromFile(BASE_PATH + "rsa_key.pub", true);

        //read all my messages
        readAllMyMessages(privateKey);

//publish message
        sendMessageTo("nando", "hallo hallo, ivar heir");

// verify all messages
        verifyAll();

// send a signed message
        signMessage(privateKey, "ivar", "corneel", encrypt(getPublicKeyFor("corneel"), "helemaal en echt van mij, of niet?"));
    }

    private static String encrypt(Key key, String input) throws Exception {
        var cipher = Cipher.getInstance(PLAIN_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encBytes);
    }

    private static String decrypt(Key key, byte[] input) throws Exception {
        Cipher decryptCipher = Cipher.getInstance(PLAIN_RSA);
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedMessageBytes;
        try {
            decryptedMessageBytes = decryptCipher.doFinal(input);
        } catch(Exception ex) {
            // try other algorithms etc
            return null;
        }
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    private static void sendMessageTo(String receiver, String message) throws Exception {
        String encrypted = encrypt(getPublicKeyFor(receiver), message);
        RestClient.publishEncryptedMessage(new EncryptedMessage(0, ME, receiver, encrypted));
    }

    private static Key getPublicKeyFor(String receiver) throws Exception {
        List<PublicKey> allKeys = getAllPublicKeys();
        return allKeys.stream().filter(k -> k.getOwner().equals(receiver)).findFirst().get().getPublicKey();
    }

    private static List<PublicKey> getAllPublicKeys() throws Exception {
        return Arrays.stream(RestClient.getAllPublicKeys())
                .filter(Main::isValidPublicKey)
                .toList();
    }

    private static boolean isValidPublicKey(PublicKey key) {
        try {
            // sanitize whitespace, newlines and PEM format
            String toVerify = key.getKey()
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "")
                    .replace("\\n", "");

            Key publicKey = publicKeyFromString(toVerify);
            key.setPublicKey(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static Key publicKeyFromString(String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        KeyFactory kf = KeyFactory.getInstance(PLAIN_RSA);
        EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(keySpec);
    }

    //TODO add hashing
    public static void signMessage(Key privateKey, String sender, String receiver, String message) throws Exception {
        String signature = encrypt(privateKey, message);
        RestClient.publishSignedMessage(new SignedMessage(0, sender, receiver, message, signature));
    }

    // TODO add hashing
    public static void verifyAll() throws Exception {
        List<PublicKey> keys = getAllPublicKeys();
        SignedMessage[] messages = RestClient.getAllSignedMessages();

        Arrays.stream(messages).forEach(message -> {
            try {
                verifySignedMessage(message, keys);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private static void verifySignedMessage(SignedMessage message, List<PublicKey> keys) throws Exception {
        for (PublicKey publicKye : keys) {
            // either use the b64 decoded payload or plaintext message
            byte[] signature = Base64.getDecoder().decode(message.getSignature());
            String decrypted = decrypt(publicKye.getPublicKey(), signature);
            if (message.getMessage().equals(decrypted) || decrypted != null) {
                System.out.println("Found a decryption match ["+ message.getMessage().equals(decrypted)+"] for message: " + message.getMessage() + " from " + message.getSender() + " is sent by: " + publicKye.getOwner() + "; decrypted: " + decrypted);
                return;
            }
        }
    }

    public static void readAllMyMessages(Key privateKey) throws Exception {
        Arrays.stream(RestClient.getAllEncryptedMessages())
                .filter(message -> message.getReceiver().equals(ME))
                .forEach(message -> {
                    try {
                        System.out.println("Decrypted \t " + message.getSender() + "\t" + decrypt(privateKey, Base64.getDecoder().decode(message.getMessage())));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
    }

    private static Key readKeyFromFile(String keyFile, boolean isPublic) throws Exception {
        File publicKeyFile = new File(keyFile);
        byte[] keyBytes = Files.readAllBytes(publicKeyFile.toPath());
        KeyFactory kf = KeyFactory.getInstance(PLAIN_RSA);
        EncodedKeySpec keySpec = isPublic ? new X509EncodedKeySpec(keyBytes) : new PKCS8EncodedKeySpec(keyBytes);
        return isPublic ? kf.generatePublic(keySpec) : kf.generatePrivate(keySpec);
    }

}