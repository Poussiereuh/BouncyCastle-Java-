package seg_as;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.sql.Timestamp;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.*;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;


public class Asymetric {
	
	
	public static String getHexString(byte[] b) throws Exception { //String hex = Hex.tohexstring(byte[]) on bouncy castle
        String result = "";
        for (int i=0; i < b.length; i++) {
            result +=
                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
	
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	    	data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	} 
	
	
	public static AsymmetricCipherKeyPair GenerateKeys() throws NoSuchAlgorithmException{

		RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
		 generator.init(new RSAKeyGenerationParameters
		     (
		    	 BigInteger.valueOf(65537),//publicExponent
		    	 new SecureRandom(),//pseudorandom number generator
		         1024,//strength
		         10//certainty
		     ));

		 return generator.generateKeyPair();
	}
	
	public static String Encrypt(byte[] data, AsymmetricKeyParameter publicKey) throws Exception{
		//encrypt the plaintext
		Security.addProvider(new BouncyCastleProvider());
		
		RSAEngine engine = new RSAEngine();
		engine.init(true, publicKey); //true for encrypt
			
		byte[] hexEncodedCipher = engine.processBlock(data, 0, data.length);
		
		return getHexString(hexEncodedCipher);
	}
	
	public static String Decrypt(String encrypted, AsymmetricKeyParameter privateKey) throws InvalidCipherTextException{
		//decrypts the encrypted text
		
		Security.addProvider(new BouncyCastleProvider());
		
		AsymmetricBlockCipher engine = new RSAEngine();
		engine.init(false, privateKey); //false if decryption
		
		byte[] encryptedBytes = hexStringToByteArray(encrypted);
		byte[] hexEncodedCipher = engine.processBlock(encryptedBytes, 0, encryptedBytes.length);
		
		return new String (hexEncodedCipher);
	}
	
	
	
	public static void saveExponentModulus(BigInteger modulus, BigInteger exponent, String file) throws IOException
	{
		// Save Exponent and Modulus in file (name of the file = String file)
		
		
		//convert string to hex
		String KeyModHex = modulus.toString(16);
		String KeyExpHex = exponent.toString(16);
		
		BufferedWriter bw = null;
		FileWriter fw = null;
		
		System.out.println("Save Exponent/Modulus in "+file);
		
		System.out.println("Modulus in Hex: "+KeyModHex);
		System.out.println("Exponent in Hex: "+KeyExpHex);
		
		File file2 = new File(file);
		
		if (!file2.exists()) {
		     file2.createNewFile();
		  }
		
		try {
			
			fw = new FileWriter(file);
			bw = new BufferedWriter(fw);
			bw.write(KeyModHex+"\r\n"); //write the modulus (in hexa) + the carriage return + return to the line in the file
			bw.write(KeyExpHex); // write the exponent in the file
			
			bw.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("--------------");
		
	}
	
	
	public static BigInteger[] importExponentModulus(String file) throws IOException
	{
		//import Exponent and Modulus
		BufferedReader br = null;
		FileReader fr = null;
		
		String module = null;
		String exposant = null;

		try {

			fr = new FileReader(file);
			br = new BufferedReader(fr);

			String sCurrentLine;

			module = sCurrentLine = br.readLine();
			System.out.println(sCurrentLine);
			exposant = sCurrentLine = br.readLine();
			System.out.println(sCurrentLine);

		} catch (IOException e) {

			e.printStackTrace();
		}
		
		BigInteger moduleBigInt = new BigInteger(module, 16);
		BigInteger expoBigInt = new BigInteger(exposant, 16);
		

		BigInteger TableModExp[] = {moduleBigInt, expoBigInt};
		
		return TableModExp; //Return an array with Modulus as a BigInt at position [0] and Exponent at position [1]
	}
	
	
	public static String importFileContent(String file) throws IOException
	{
		//Import the content of file
		BufferedReader br = null;
		FileReader fr = null;
		
		String text = "";

		try {

			fr = new FileReader(file);
			br = new BufferedReader(fr);

			String sCurrentLine;

			sCurrentLine = br.readLine();
			text = sCurrentLine;

		} catch (IOException e) {

			e.printStackTrace();
		}
		
		
		return text;
	}
	
	public static String importFileContent2(String file) throws IOException
	{
		//Import the content of file
		BufferedReader br = null;
		FileReader fr = null;
		
		String text = "";

		try {

			fr = new FileReader(file);
			br = new BufferedReader(fr);

			String sCurrentLine;
			while ((text = br.readLine()) != null)
			{
			sCurrentLine = br.readLine();
			text = text + sCurrentLine;
			}
			System.out.print(text);
		} catch (IOException e) {

			e.printStackTrace();
		}
		
		
		return text;
	}
	
	public static void saveContent(String nameofthefile, String content) throws IOException
	{
		//save the content of a string inside "nameofthefile" 
		BufferedWriter bw = null;
		FileWriter fw = null;
		File file = new File(nameofthefile);
		
		if (!file.exists()) {
		     file.createNewFile();
		  }


		try {
					fw = new FileWriter(nameofthefile);
					bw = new BufferedWriter(fw);
					bw.write(content);
					bw.close();
				}
				catch(Exception e) {
					e.printStackTrace();
				}
		
	}
	
//	public static String digest(String plainMessage1, RSAKeyParameters keyRegesign) throws IOException
//	{
//		MessageDigest sha = MessageDigest.getInstance("SHA-256");
//		sha.update(plainMessage1.getBytes());
//        byte[] digest = sha.digest();
//        String encrypteMessageDigest = Asymetric.Encrypt(digest, keyRegesign);
//        System.out.println(encrypteMessageDigest);
//		
//        return encrypteMessageDigest;
//	}
	
}