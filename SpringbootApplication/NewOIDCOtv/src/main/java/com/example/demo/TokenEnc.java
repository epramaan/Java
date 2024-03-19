package com.example.demo;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class TokenEnc {

	Cipher cipher;
	static String ALGO = "AES";

	public TokenEnc() throws NoSuchAlgorithmException, NoSuchPaddingException {
		// "AES/CBC/PKCS5Padding"
		this.cipher = Cipher.getInstance("AES");
	}

	public String encrypt(String plainText, String seed, String salt) throws Exception {
		System.out.println("--------Inside Encrypt method---------------");
		SecretKeySpec secretKeySpec = (SecretKeySpec) generateKey(seed);
		System.out.println("Text received : " + plainText);

		System.out.println("Seed : " + seed);
		byte[] plainTextByte = (plainText + salt).getBytes();

		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		System.out.println("-----------KEY initialized----------");
		byte[] encryptedByte = cipher.doFinal(plainTextByte);
//		String encryptedText = Base64.getEncoder().encode(encryptedByte).toString();
		String encryptedText = Base64.encodeBase64String(encryptedByte);
		System.out.println("Encrypted Text : " + encryptedText);
		System.out.println("--------Encryption completed---------------");
		return encryptedText;
	}

	public String decrypt(String encryptedText, String seed, String salt) throws Exception {
		System.out.println("--------Inside Decrypt method---------------");
		SecretKeySpec secretKeySpec = (SecretKeySpec) generateKey(seed);
		//byte[] encryptedTextByte = Base64.getDecoder().decode(encryptedText);
		byte[] encryptedTextByte = Base64.decodeBase64(encryptedText);
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
		String decryptedText = new String(decryptedByte);

		System.out.println("Base64 decoded and decrypted text : " + decryptedText);

		decryptedText = decryptedText.substring(0, decryptedText.lastIndexOf(salt));
		System.out.println("Decrypted Text : " + decryptedText);
		System.out.println("--------Decryption completed---------------");
		return decryptedText;
	}

	public Key generateKey(String seed) {
		System.out.println("---------------Inside generateKey method------------");
		System.out.println("Seed : " + seed);
		MessageDigest sha256 = null;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		}
		byte[] passBytes = seed.getBytes();
		byte[] passHash = sha256.digest(passBytes);
		SecretKeySpec secretKeySpec = new SecretKeySpec(passHash, ALGO);

		System.out.println("---------------Key generated successfully------------");
		return secretKeySpec;
	}

	
}
