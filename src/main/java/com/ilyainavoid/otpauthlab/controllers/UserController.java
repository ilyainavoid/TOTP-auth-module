package com.ilyainavoid.otpauthlab.controllers;

import com.bettercloud.vault.json.JsonArray;
import com.bettercloud.vault.json.JsonObject;
import com.bettercloud.vault.json.ParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import com.ilyainavoid.otpauthlab.helpers.AppConstants;
import com.ilyainavoid.otpauthlab.models.dtos.*;
import com.ilyainavoid.otpauthlab.models.entities.User;
import com.ilyainavoid.otpauthlab.repositories.UserRepository;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.entities.channel.concrete.TextChannel;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.tomcat.util.json.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.LoginException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

@RestController
public class UserController {

    private final UserRepository userRepository;
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private static final String IAM_TOKEN = AppConstants.IAM_TOKEN;
    private static final String BOT_TOKEN = AppConstants.BOT_TOKEN;
    private static final String CHANNEL_ID = AppConstants.CHANNEL_ID;
    private static final String GET_URL = AppConstants.GET_URL;
    private static final String CREATE_URL = AppConstants.CREATE_URL;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostMapping("api/login")
    public ResponseEntity<ResponseDto> login(@RequestBody LoginData loginData) throws IOException {
        User user = userRepository.findByUsername(loginData.getUsername());
        if (passwordEncoder.matches(loginData.getPassword(), user.getHashedPassword())) {
            ResponseDto responseData = new ResponseDto(200, "Data is valid! Waiting for OTP!");
            ResponseEntity<ResponseDto> response = new ResponseEntity<>(responseData, HttpStatus.OK);
            String symmetricKey = user.getSymmetricKey();
            String secret = decryptSecret(fetchSecret(user.getSecretId()), symmetricKey);
            String TOTP = generateTOTP(secret);
            sendMessage(TOTP);
            return response;
        } else {
            ResponseDto responseData = new ResponseDto(500, "Error occured!");
            ResponseEntity<ResponseDto> response = new ResponseEntity<>(responseData, HttpStatus.INTERNAL_SERVER_ERROR);
            return response;
        }
    }

    @PostMapping("/api/submitOTP")
    public ResponseEntity<ResponseDto> submitLogin(@RequestBody SubmitOTP data) {
        User user = userRepository.findByUsername(data.getUsername());
        try {
            String symmetricKey = user.getSymmetricKey();
            String secret = decryptSecret(fetchSecret(user.getSecretId()), symmetricKey);
            String generatedTOTP = generateTOTP(secret);
            if (generatedTOTP.equals(data.getCode())) {
                ResponseDto responseData = new ResponseDto(200, "Пользователь авторизован!");
                return new ResponseEntity<>(responseData, HttpStatus.OK);
            }
            else {
                ResponseDto responseData = new ResponseDto(500, "Неверный код!");
                return new ResponseEntity<>(responseData, HttpStatus.OK);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("api/register")
    public ResponseEntity<ResponseDto> register(@RequestBody UserRegisterDto userData) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String hashedPassword = passwordEncoder.encode(userData.getPassword());
        Key key = getPasswordBasedKey("AES", 128, userData.getPassword().toCharArray());
        String symmetricKey = keyToString(key);
        String secret = generateSecret();
        secret = encryptSecret(secret, key);
        String secretId = addSecretToLockbox(userData.getUsername(), secret, "b1gjha6i766r3pm79ckd");
        User newUser = new User();
        newUser.setId(UUID.randomUUID());
        newUser.setUsername(userData.getUsername());
        newUser.setHashedPassword(hashedPassword);
        newUser.setSymmetricKey(symmetricKey);
        newUser.setSecretId(secretId);
        userRepository.save(newUser);

        ResponseDto responseData = new ResponseDto(200, "User has been signed up!");
        ResponseEntity<ResponseDto> response = new ResponseEntity<>(responseData, HttpStatus.OK);
        return response;
    }

    public static String encryptSecret(String secret, Key symmetricKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            byte[] encryptedSecretBytes = cipher.doFinal(secret.getBytes());
            return Base64.getEncoder().encodeToString(encryptedSecretBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptSecret(String secret, String symmetricKey) {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(symmetricKey);
            SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] encryptedBytes = Base64.getDecoder().decode(secret);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void sendMessage(String message) {

        try {
            TextChannel channel = JDABuilder.createDefault(BOT_TOKEN)
                    .build()
                    .awaitReady()
                    .getTextChannelById(CHANNEL_ID);

            channel.sendMessage(message).queue();
        } catch (Exception e) {
            System.err.println("Failed to send message: " + e.getMessage());
        }
    }

    //Метод для получения секрета с Yandex Lockbox
    public static String fetchSecret(String secretId) throws IOException, ParseException {
        URL url = new URL(GET_URL);

        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpget = new HttpGet("https://payload.lockbox.api.cloud.yandex.net/lockbox/v1/secrets/" + secretId + "/payload");
            httpget.setHeader("Authorization", "Bearer " + IAM_TOKEN);
            httpget.setHeader("Content-Type", "application/json");
            CloseableHttpResponse response = httpClient.execute(httpget);

            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
            String responseBody = stringBuilder.toString();

            if (responseBody != null && !responseBody.isEmpty()) {
                ObjectMapper mapper = new ObjectMapper();
                LockboxPayload lockboxPayload = mapper.readValue(responseBody, LockboxPayload.class);

                if (lockboxPayload != null && lockboxPayload.getEntries() != null && !lockboxPayload.getEntries().isEmpty()) {
                    SecretDto firstEntry = lockboxPayload.getEntries().get(0);
                    String secret = firstEntry.getTextValue();
                    System.out.println("Secret: " + secret);

                    return secret;

                } else {
                    System.out.println("No entries found.");
                    return null;
                }
            } else {
                System.out.println("Empty response.");
                return null;
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    //Метод для сереализации Char[] в String
    private static String keyToString(Key key) {
        // Получаем байтовый массив из ключа
        byte[] keyBytes = key.getEncoded();
        // Кодируем байтовый массив в строку Base64
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    private static String generateSecret() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] secretBytes = new byte[16];
        secureRandom.nextBytes(secretBytes);
        String secret = Base64.getEncoder().encodeToString(secretBytes);
        return secret;
    }

    //Генерация симметричного ключа на основе пароля
    private static Key getPasswordBasedKey(String cipher, int keySize, char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[100];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 1000, keySize);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        return new SecretKeySpec(pbeKey.getEncoded(), cipher);
    }

    public static String generateTOTP(String secret) {
        long timeStep = 30;
        long unixTime = System.currentTimeMillis() / 1000 / timeStep;
        String time = Long.toHexString(unixTime).toUpperCase();

        while (time.length() < 16) {
            time = "0" + time;
        }

        byte[] secretBytes = secret.getBytes();
        byte[] timeBytes = hexStringToBytes(time);

        try {
            Mac mac = Mac.getInstance("HMACSHA1");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretBytes, "RAW");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(timeBytes);

            int offset = hmacBytes[hmacBytes.length - 1] & 0xf;

            int truncated = ((hmacBytes[offset] & 0x7f) << 24) |
                    ((hmacBytes[offset + 1] & 0xff) << 16) |
                    ((hmacBytes[offset + 2] & 0xff) << 8) |
                    (hmacBytes[offset + 3] & 0xff);

            int generatedCodeInteger = truncated % 1000000;

            String generatedCodeString = Integer.toString(generatedCodeInteger);
            while (generatedCodeString.length() < 6) {
                generatedCodeString = "0" + generatedCodeString;
            }
            return generatedCodeString;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }
    private static byte[] hexStringToBytes(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    private static String addSecretToLockbox(String username, String secretValue, String folderId) throws IOException, ParseException {

        JsonObject body = new JsonObject();
        body.add("folderId", folderId);
        body.add("name", username);
        body.add("description", "OTP-secret for user " + username);
        body.add("versionDescription", "");

        JsonArray versionPayloadEntries = new JsonArray();
        JsonObject versionPayloadEntry = new JsonObject();
        versionPayloadEntry.add("key", "OTP-secret");
        versionPayloadEntry.add("textValue", secretValue);
        versionPayloadEntries.add(versionPayloadEntry);

        body.add("versionPayloadEntries", versionPayloadEntries);
        body.add("deletionProtection", false);

        URL url = new URL(CREATE_URL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + IAM_TOKEN);
        connection.setDoOutput(true);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = body.toString().getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                StringBuilder responseBuilder = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    responseBuilder.append(line);
                }
                String response = responseBuilder.toString();
                SecretAddResponse responseDTO = SecretAddResponse.fromJson(response);
                return responseDTO.getMetadata().getSecretId();
            }
        } else {
            throw new IOException("HTTP error code: " + responseCode);
        }
    }
}
