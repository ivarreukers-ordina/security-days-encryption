package encryption;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class RestClient {
    private static final String QUARKUS_COOKIE = "quarkus-credential=DA0Pw9aAgPI9/WFBo9pgTtxoAbujUmoH2gj5eGOsl8UXZnFOy9+oR67tBPgCw6A=";

    static EncryptedMessage[] getAllEncryptedMessages() throws Exception {
        URL url = new URL("http://172.27.4.37:8080/encryptedMessages");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.addRequestProperty("Cookie", QUARKUS_COOKIE);

        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(new InputStreamReader(con.getInputStream()), EncryptedMessage[].class);
    }

    static SignedMessage[] getAllSignedMessages() throws Exception {
        URL url = new URL("http://172.27.4.37:8080/signedMessages");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.addRequestProperty("Cookie", QUARKUS_COOKIE);

        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(new InputStreamReader(con.getInputStream()), SignedMessage[].class);
    }

    public static PublicKey[] getAllPublicKeys() throws Exception {
        URL url = new URL("http://172.27.4.37:8080/publicKeys");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.addRequestProperty("Cookie", QUARKUS_COOKIE);

        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(new InputStreamReader(con.getInputStream()), PublicKey[].class);
    }

    public static void publishEncryptedMessage(EncryptedMessage message) throws Exception {
        URL url = new URL("http://172.27.4.37:8080/encryptedMessages");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.addRequestProperty("Content-Type", "application/json");
        con.addRequestProperty("Cookie", QUARKUS_COOKIE);
        con.setDoOutput(true);
        String jsonInputString = new ObjectMapper().writeValueAsString(message);
        try(OutputStream os = con.getOutputStream()) {
            byte[] input = jsonInputString.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        try(BufferedReader br = new BufferedReader(
                new InputStreamReader(con.getInputStream(), "utf-8"))) {
            StringBuilder response = new StringBuilder();
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            System.out.println(response.toString());
        }
    }

    public static void publishSignedMessage(SignedMessage message) throws Exception {
        URL url = new URL("http://172.27.4.37:8080/signedMessages");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.addRequestProperty("Content-Type", "application/json");
        con.addRequestProperty("Cookie", QUARKUS_COOKIE);
        con.setDoOutput(true);
        String jsonInputString = new ObjectMapper().writeValueAsString(message);
        try(OutputStream os = con.getOutputStream()) {
            byte[] input = jsonInputString.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        try(BufferedReader br = new BufferedReader(
                new InputStreamReader(con.getInputStream(), "utf-8"))) {
            StringBuilder response = new StringBuilder();
            String responseLine = null;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
            System.out.println(response.toString());
        }
    }
}
