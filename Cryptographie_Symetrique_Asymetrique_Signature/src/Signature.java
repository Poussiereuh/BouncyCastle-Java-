import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Scanner;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;






public class Signature {





	public static void sign() throws IOException, InvalidCipherTextException {

		//INITIALIZATION OF THE DIGEST FOR THE HASH
		Digest hashSHA256 = new SHA256Digest();




		//SELECTION OF THE FILE TO SIGN
		Scanner si = new Scanner(System.in);
		System.out.println("Please specify the name of the file to sign :"); 
		String nFileToHash = si.next(); 


		//GET THE CONTENT OF THE FILE



		FileInputStream fIn = new FileInputStream(nFileToHash);

		byte buffer []  = new byte[8192];
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		int c;
		while ((c = fIn.read(buffer)) != -1) {
			os.write(buffer, 0, c);

		}
		byte fileToHash [] = os.toByteArray();
		fIn.close();
		os.close();


		//HASH OF THE FILE CONTENT
		byte [] hash = new byte[hashSHA256.getDigestSize()];//declare a byte array which will handle the content of the hash of the file

		hashSHA256.update(fileToHash, 0, fileToHash.length);

		hashSHA256.doFinal(hash, 0);

		System.out.println("The hash value of the file is :"+Hex.toHexString(hash));




		//KEY SELECTION FOR HASH ENCRYPTION
		System.out.println("Please specify the name of the key to use :"); 
		String nKey = si.next(); 

		String modHex = Files.readAllLines(Paths.get(nKey)).get(0);
		String expHex = Files.readAllLines(Paths.get(nKey)).get(1);

		BigInteger mod = new BigInteger(modHex, 16);
		BigInteger exp = new BigInteger(expHex, 16);


		//CONSTRUCTION OF THE KEY
		RSAKeyParameters key = new RSAKeyParameters(true, mod, exp);//true for is private 


		//CONSTRUCTION OF THE CIPHER FOR ENCRYPTION

		AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());

		cipher.init(true, key);//true for encryption
		byte[] hashToEncrypt = hash;
		byte[] encrypted = cipher.processBlock(hashToEncrypt, 0, hashToEncrypt.length);//proceed the encryption

		System.out.println("The signed value of the file is :"+ Hex.toHexString(encrypted));

		//STORAGE OF THE SIGNED FILE

		System.out.println("Please specify the name of the encrypted file for storage :");
		String nFile = si.next(); //nFile = name of the encrypted file
		System.out.println("Your file will be stored in a file named " + nFile); 
		File file = new File(nFile);
		if(!file.exists()) {
			file.createNewFile();
		}
		BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(file));
		fileOut.write(encrypted);

		fileOut.close();




	}		

	public static void verify() throws IOException, InvalidCipherTextException {


		//INITIALIZATION OF THE DIGEST FOR THE HASH
		Digest hashSHA256 = new SHA256Digest();
		//CHOICE OF THE ORIGINAL FILE FOR COMPARAISON
		Scanner si = new Scanner(System.in);
		System.out.println("Please specify the name of the original file for verification :"); 
		String nOriginalFile = si.next(); 

		//GET THE CONTENT OF THE ORIGINAL FILE


		FileInputStream fIn = new FileInputStream(nOriginalFile);

		byte buffer []  = new byte[8192];
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		int c;
		while ((c = fIn.read(buffer)) != -1) {
			os.write(buffer, 0, c);

		}
		byte originalFile [] = os.toByteArray();
		fIn.close();
		os.close();
		//HASH OF THE ORIGINAL FILE CONTENT FOR LATER COMPARISON
		byte [] hash = new byte[hashSHA256.getDigestSize()];

		hashSHA256.update(originalFile, 0, originalFile.length);

		hashSHA256.doFinal(hash, 0);

		System.out.println("The hash value of the file is :"+Hex.toHexString(hash));


		//SIGNED FILE SELECTION FOR LATER COMPARISON
		System.out.println("Please specify the name of the signed file for verification :"); 
		String nSignedFile = si.next();

		//GET THE CONTENT OF THE SIGNED FILE



		FileInputStream fIn2 = new FileInputStream(nSignedFile);

		byte buffer2 []  = new byte[8192];
		ByteArrayOutputStream os2 = new ByteArrayOutputStream();
		int c2;
		while ((c2 = fIn2.read(buffer2)) != -1) {
			os2.write(buffer2, 0, c2);

		}
		byte signedFile [] = os2.toByteArray();
		fIn2.close();
		os2.close();



		//KEY SELECTION TO DECRYPT THE SIGNED FILE
		System.out.println("Please specify the key to use for verification :"); 
		String nKey = si.next();
		String modHex = Files.readAllLines(Paths.get(nKey)).get(0);
		String expHex = Files.readAllLines(Paths.get(nKey)).get(1);

		BigInteger mod = new BigInteger(modHex, 16);
		BigInteger exp = new BigInteger(expHex, 16);


		//CONSTRUCTION OF THE KEY
		RSAKeyParameters key = new RSAKeyParameters(false, mod, exp);

		//CONSTRUCTION OF THE CIPHER TO DECRYPT THE SIGNED FILE

		AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
		cipher.init(false, key);//false for decryption

		byte[] decryptedFile = cipher.processBlock(signedFile, 0, signedFile.length);

		//COMPARISON BETWEEN DECRYPTED SIGNED FILE AND THE HASH OF THE ORIGINAL FILE

		if (Arrays.equals(decryptedFile, hash))
		{
			System.out.println("The signature is valid");
		}
		else {
			System.out.println("The signature is not valid");
		}



	}



}
