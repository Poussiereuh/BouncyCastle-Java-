import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class Asymetric {

	static int l = 1024;

	public static void generateKey () {

		Scanner si = new Scanner(System.in);
		System.out.println("Please specify the name of the public key :");
		String nPublicKey = si.nextLine(); //nPublicKey = name of the public key 
		System.out.println("Your public key is will be stored in a file named :" + nPublicKey);
		System.out.println("Please specify the name of the private key :");
		String nPrivateKey = si.nextLine(); //nPrivateKey = name of the private key
		System.out.println("Your private key is will be stored in a file named :" + nPrivateKey);


		//KEY GENERATION
		RSAKeyGenerationParameters keyParam = new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 1024, 100);//declaration of the key generator parameters
		RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();//declaration of the the key generator
		keyGen.init(keyParam);//initialize le key generator with the parameters 

		AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

		RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();//get the public key of the pair
		RSAKeyParameters privateKey = (RSAKeyParameters) keyPair.getPrivate();//get the private key of the pair

		//GET MODULE AND EXPONENT OF THE KEYS

		BigInteger publicKeyExp = publicKey.getExponent();//get the exponent of the public key
		BigInteger publicKeyMod = publicKey.getModulus();//get the modulus of the public key

		BigInteger privateKeyExp = privateKey.getExponent();//get the exponent of the private key
		BigInteger privateKeyMod = privateKey.getModulus();//get the modulus of the private key

		//CONVERT TO HEXADECIMAL BEFORE STORAGE

		String privateKeyExpHex = privateKeyExp.toString(16);	
		String privateKeyModHex = privateKeyMod.toString(16);	
		String publicKeyExpHex = publicKeyExp.toString(16);	
		String publicKeyModHex = publicKeyMod.toString(16);	



		//STORAGE OF THE KEYS IN DIFFERENT FILES
		try {
			File file = new File(nPublicKey);
			if(!file.exists()) {
				file.createNewFile();//create a new file if the file doesn't exist yet
			}
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));//declaration of a new bufferedwriter with a FOS as parameter 
			writer.write(publicKeyModHex+"\r\n");//write the modulus and the exponent of the key with CRLF
			writer.write(publicKeyExpHex);
			writer.close();//close the writer
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		//same as above for the private key
		try {
			File file = new File(nPrivateKey);
			if(!file.exists()) {
				file.createNewFile();
			}
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
			writer.write(privateKeyModHex+"\r\n"); 
			writer.write(privateKeyExpHex); 
			writer.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}


		//STORAGE OF THE KEY IN PEM FORMAT
		GuardarFormatoPEM.guardarClavesPEM(publicKey, privateKey);



	}


	public static void encryptWithRSA () throws InvalidCipherTextException, IOException {


		System.out.println("Please specify the name of the key to use for encryption :");
		Scanner si = new Scanner(System.in);

		//KEY SELECTION FOR ENCRYPTION

		String nKey = si.next(); 


		//GET THE MOD AND EXP OF THE KEY FROM THE FILE

		String modHex = Files.readAllLines(Paths.get(nKey)).get(0);//get the first line of the file which contain the modulus and exponent of the key
		String expHex = Files.readAllLines(Paths.get(nKey)).get(1);//get the second line

		BigInteger mod = new BigInteger(modHex, 16);//convert the hex value of the modulus to a biginteger
		BigInteger exp = new BigInteger(expHex, 16);//same for the exp

		//CONSTRUCTION OF THE THE KEY 
		RSAKeyParameters key = new RSAKeyParameters(false, mod, exp);//false for the condition "is private"


		//SELECTION OF THE FILE TO ENCRYPT

		System.out.println("Please specify the name of the clear file for encrypt :");
		String nClearFile = si.next(); //nClearFile = name of the clear file
		System.out.println("You will encrypt the file named " + nClearFile);



		//GET THE CONTENT OF THE FILE

		String nF = nClearFile;
		FileInputStream fIn = new FileInputStream(nF);

		byte buffer []  = new byte[8192];//declare a buffer to handle the content of the file
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		int c;
		while ((c = fIn.read(buffer)) != -1) {
			os.write(buffer, 0, c);

		}
		byte fileToEncrypt [] = os.toByteArray();//get the exact length of the content of the file
		os.close();
		fIn.close();

		String hexToEncrypt = Hex.toHexString(fileToEncrypt);
		System.out.println("The hexa value of the file to encrypt is :"+hexToEncrypt);

		//CONSTRUCTION OF THE CIPHER FOR ENCRYPTION

		AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());

		cipher.init(true, key);//initialization of the cipher (with true for encryption)
		byte[] toEncrypt = fileToEncrypt;
		byte[] encrypted = cipher.processBlock(toEncrypt, 0, toEncrypt.length);//proceed the encryption

		//STORAGE OF THE ENCRYPTED FILE

		System.out.println("Please specify the name of the encrypted file for storage :");
		String nFile = si.next(); //nFile = name of the encrypted file
		System.out.println("Your file will be stored in a file named :" + nFile); 
		File file = new File(nFile);
		if(!file.exists()) {
			file.createNewFile();
		}
		BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(file));
		fileOut.write(encrypted);

		fileOut.close(); 


	}


	public static void decryptWithRSA () throws InvalidCipherTextException, IOException {


		//KEY SELECTION FOR DECRYPTION
		Scanner si = new Scanner(System.in);
		System.out.println("Please specify the name of the key to use for decryption :"); 
		String nKey = si.next(); 


		//GET THE MOD AND EXP FROM THE FILE


		String modHex = Files.readAllLines(Paths.get(nKey)).get(0);
		String expHex = Files.readAllLines(Paths.get(nKey)).get(1);

		BigInteger mod = new BigInteger(modHex, 16);
		BigInteger exp = new BigInteger(expHex, 16);


		//CONSTRUCTION OF THE KEY

		RSAKeyParameters key = new RSAKeyParameters(true, mod, exp);//true for "is private" 


		//SELECTION OF THE FILE TO DECRYPT

		System.out.println("Please specify the name of the crypted file for decryption :");
		String nEncryptedFile = si.next(); //nEncryptedFile= name of the encrypted file
		System.out.println("Your will decrypt the file named :" + nEncryptedFile);


		//GET THE CONTENT OF THE FILE
		FileInputStream fIn = new FileInputStream(nEncryptedFile);



		byte buffer []  = new byte[8192];
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		int c;
		while ((c = fIn.read(buffer)) != -1) {
			os.write(buffer, 0, c);

		}
		byte fileToDecrypt [] = os.toByteArray();
		os.close();
		fIn.close();



		//CONSTRUCTION OF THE CIPHER FOR DECRYPTION

		AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
		cipher.init(false, key);//false for decryption

		byte[] decryptedCipher = cipher.processBlock(fileToDecrypt, 0, fileToDecrypt.length);

		//STORAGE OF THE DECRYPTED FILE

		System.out.println("Please specify the name of the decryted file for storage :");
		String nDecryptedFile = si.next();
		System.out.println("The name of the decrypted file is :" + nDecryptedFile);

		try {
			File file = new File(nDecryptedFile);
			if(!file.exists()) {
				file.createNewFile();
			}
			BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(file));
			fileOut.write(decryptedCipher);

			fileOut.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}


	}

}


