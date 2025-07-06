package org.mule.extension.Encryption.internal;

import static org.mule.runtime.extension.api.annotation.param.MediaType.ANY;
import org.mule.runtime.extension.api.annotation.param.display.DisplayName;

import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.util.Base64;
import java.util.List;
import java.security.spec.KeySpec;

import org.mule.runtime.extension.api.annotation.param.MediaType;
import org.mule.runtime.extension.api.annotation.param.Optional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.PublicKey;

import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.security.KeyFactory;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;


/**
 * This class is a container for operations, every public method in this class will be taken as an extension operation.
 */
public class EncryptionOperations {
	
    private  final byte[] SALT = {
        (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
        (byte) 0x56, (byte) 0x34, (byte) 0xE3, (byte) 0x03
    };
    private  final int ITERATION_COUNT = 19;
    
    public enum SupportedAlgorithm {
        PBEWithMD5AndDES,
        PBEWithSHA1AndDESede,
        PBEWithSHA1AndRC2_40
    }
    
    public enum AesAlgorithm {
        AES_ECB_PKCS5("AES/ECB/PKCS5Padding"),
        AES_CBC_PKCS5("AES/CBC/PKCS5Padding"),
        AES_GCM_NOPADDING("AES/GCM/NoPadding");

        private final String transformation;

        AesAlgorithm(String transformation) {
            this.transformation = transformation;
        }

        public String getTransformation() {
            return transformation;
        }
    }
    
    public enum RsaAlgorithm {
        RSA_PKCS1("RSA/ECB/PKCS1Padding"),
        RSA_OAEP("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        private final String transformation;

        RsaAlgorithm(String transformation) {
            this.transformation = transformation;
        }

        public String getTransformation() {
            return transformation;
        }
    }
    
    //encrypt using AES
    @MediaType(value = ANY, strict = false)
    @DisplayName("Encrypt with AES")
    public String encryptAESOperation(
        @DisplayName("Input Text") String input,
        @DisplayName("Key") String key,
        @DisplayName("AES Algorithm") AesAlgorithm algorithm
    ) throws Exception {
        return encryptAES(input, key, algorithm);
    }
    
    //encrypt using RSA
    @MediaType(value = ANY, strict = false)
    @DisplayName("Encrypt with RSA")
    public String rsaEncryptOperation(
        @DisplayName("Input Text") String input,
        @DisplayName("Public Key (Base64)") String base64PublicKey,
        @Optional @DisplayName("RSA Algorithm") RsaAlgorithm algorithm
    ) throws Exception {
        RsaAlgorithm algoToUse = algorithm != null ? algorithm : RsaAlgorithm.RSA_PKCS1;
        PublicKey pubKey = loadRSAPublicKey(base64PublicKey);
        return encryptRSA(input, pubKey, algoToUse.getTransformation());
    }
    
    //encrypt using Password / PBE
    @MediaType(value = ANY, strict = false)
    @DisplayName("Encrypt Partial Payload")
    public Map<String, String> encryptPartialPayload(@DisplayName("JSON Payload") String jsonPayload, @DisplayName("Fields to Encrypt (comma-separated)") String fieldList, @DisplayName("Password / Key") String password, @DisplayName("Algorithm") SupportedAlgorithm algorithm) throws Exception {
        if (jsonPayload == null || jsonPayload.trim().isEmpty()) {
            throw new IllegalArgumentException("JSON payload cannot be null or empty");
        }
        if (fieldList == null || fieldList.trim().isEmpty()) {
            throw new IllegalArgumentException("Field list cannot be null or empty");
        }

        // Convert JSON string to Map
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> inputMap = mapper.readValue(jsonPayload, new TypeReference<Map<String, String>>() {});

        // Get the list of fields to encrypt
        String[] fieldsToEncrypt = fieldList.split(",");

        for (String field : fieldsToEncrypt) {
            field = field.trim();
            if (inputMap.containsKey(field)) {
                String value = inputMap.get(field);
                String encryptedValue = encryptToBase64(value, password, algorithm.name());
                inputMap.put(field, encryptedValue); // Replace in the original map
            }
        }

        return inputMap; // Final map with a mix of encrypted and unencrypted fields
    }

    private String encryptToBase64(String input, String password, String algorithm) throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), SALT, ITERATION_COUNT);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, keyFactory.generateSecret(keySpec), new PBEParameterSpec(SALT, ITERATION_COUNT));

        byte[] encryptedBytes = cipher.doFinal(input.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    //decrypt using Password / PBE
    @MediaType(value = ANY, strict = false)
    public Map<String, String> decryptPartialPayload(
        String jsonPayload,
        String fieldList,
        String password,
        SupportedAlgorithm algorithm
    ) throws Exception {
        if (jsonPayload == null || jsonPayload.trim().isEmpty()) {
            throw new IllegalArgumentException("JSON payload cannot be null or empty");
        }
        if (fieldList == null || fieldList.trim().isEmpty()) {
            throw new IllegalArgumentException("Field list cannot be null or empty");
        }

        // Convert JSON string to Map
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> inputMap = mapper.readValue(jsonPayload, new TypeReference<Map<String, String>>() {});

        // Get the list of fields to decrypt
        String[] fieldsToDecrypt = fieldList.split(",");

        for (String field : fieldsToDecrypt) {
            field = field.trim();
            if (inputMap.containsKey(field)) {
                String encryptedValue = inputMap.get(field);
                String decryptedValue = decryptFromBase64(encryptedValue, password, algorithm.name());
                inputMap.put(field, decryptedValue); // Replace with decrypted value
            }
        }

        return inputMap; // Final map with a mix of decrypted and untouched fields
    }

    
    private String decryptFromBase64(String base64Encrypted, String password, String algorithm) throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), SALT, ITERATION_COUNT);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, keyFactory.generateSecret(keySpec), new PBEParameterSpec(SALT, ITERATION_COUNT));

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(base64Encrypted));
        return new String(decryptedBytes, "UTF-8");
    }
    
    //this method is for masking
    @MediaType(value = ANY, strict = false)
    public Map<String, String> maskPartialFields(String jsonPayload, List<MaskConfig> maskConfigs) throws Exception {
        if (jsonPayload == null || jsonPayload.trim().isEmpty()) {
            throw new IllegalArgumentException("JSON payload cannot be null or empty");
        }
        if (maskConfigs == null || maskConfigs.isEmpty()) {
            throw new IllegalArgumentException("Mask config list cannot be null or empty");
        }

        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> inputMap = mapper.readValue(jsonPayload, new TypeReference<Map<String, String>>() {});

        for (MaskConfig config : maskConfigs) {
            String field = config.getField().trim();
            if (inputMap.containsKey(field)) {
                String value = inputMap.get(field);
                String maskedValue = applyMask(value, config.getStartIndex(), config.getEndIndex(), config.getMaskChar());
                inputMap.put(field, maskedValue);
            }
        }

        return inputMap;
    }
    
    private String applyMask(String input, int start, int end, String maskChar) {
        if (input == null || input.length() == 0) return input;
        if (start < 0) start = 0;
        if (end > input.length()) end = input.length();
        if (start >= end) return input;

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            if (i >= start && i < end) {
                result.append(maskChar);
            } else {
                result.append(input.charAt(i));
            }
        }
        return result.toString();
    }
    
    private String encryptAES(String input, String key, AesAlgorithm algorithm) throws Exception {
        String transformation = algorithm.getTransformation();
        Cipher cipher = Cipher.getInstance(transformation);

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        if (transformation.contains("CBC")) {
            byte[] iv = new byte[16]; // use random in real apps
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        } else if (transformation.contains("GCM")) {
            byte[] iv = new byte[12]; // standard IV size for GCM
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        byte[] encrypted = cipher.doFinal(input.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    private PublicKey loadRSAPublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private String encryptRSA(String input, PublicKey publicKey, String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

}
