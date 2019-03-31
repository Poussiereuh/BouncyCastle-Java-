package seg_as;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex; 







public class Symetric {


	public static void encryptWithRijndaelCBC() throws IOException 
	{ 

		try { 


			//INITIALIZATION OF AN IV
			byte[] IV = new byte[24];//24 bytes IV = 192 bits, same size as the blocks 
			SecureRandom.getInstance("SHA1PRNG").nextBytes(IV);
			String IVinHex = Hex.toHexString(IV);
			System.out.println("the generated IV is :" +IVinHex);

			System.out.println("Please specify the name of the key to use for encryption :");
			Scanner si = new Scanner(System.in);

			//KEY SELECTION FOR ENCRYPTION

			String nKey = si.next(); 


			//GET THE KEY FROM THE FILE

			FileInputStream fIn = new FileInputStream(nKey);


			byte buffer []  = new byte[8192];
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			int c;
			while ((c = fIn.read(buffer)) != -1) {
				os.write(buffer, 0, c);
				os.close();
			}
			byte key [] = Hex.decode(os.toByteArray());
			os.close();
			fIn.close();

			String keyHex = Hex.toHexString(key);
			System.out.println("You key is :"+keyHex);


			//CHOICE OF THE FILE TO ENCRYPT

			System.out.println("Please specify the name of the clear file for encryption :");
			String nClearFile = si.next(); //nClearFile = name of the clear file
			System.out.println("You will encrypt the file named :" + nClearFile);



			//GET THE CONTENT OF THE FILE

			String nF = nClearFile;
			FileInputStream fIn2 = new FileInputStream(nF);

			byte buffer2 []  = new byte[8192];
			ByteArrayOutputStream os2 = new ByteArrayOutputStream();
			int c2;
			while ((c2 = fIn2.read(buffer2)) != -1) {
				os2.write(buffer2, 0, c2);

			}
			byte fileToEncrypt [] = os2.toByteArray();
			os2.close();
			fIn2.close();

			String hexToEncrypt = Hex.toHexString(fileToEncrypt);
			System.out.println("The hexa value of the file to encrypt is :"+hexToEncrypt);

			//CIPHER CONSTRUCTION FOR ENCRYPTION

			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RijndaelEngine(192)), new X923Padding());//192 for the block size of rijndael, using CBC and X923 padding  
			CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), IV); 
			cipher.init(true, ivAndKey);//true for encryption
			byte [] encrypted = cipherData(cipher, fileToEncrypt);
			System.out.println("The encrypted hex is :" + Hex.toHexString(cipherData(cipher, fileToEncrypt)));

			//STORAGE OF THE ENCRYPTED FILE

			System.out.println("Please specify the name of the encrypted file for storage :");
			String nFile = si.next(); //nFile = name of the encrypted file
			System.out.println("Your file will be stored in a file named " + nFile); 
			File file = new File(nFile);
			if(!file.exists()) {
				file.createNewFile();
			}
			BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(file));
			fileOut.write(IV);
			fileOut.write(encrypted);

			fileOut.close(); 

		} catch (InvalidCipherTextException e) { 
			throw new RuntimeException(e); 
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	} 


	public static void decryptWithRijndaelCBC() 
	{ 
		try { 

			//KEY SELECTION FOR DECRYPTION
			Scanner si = new Scanner(System.in);
			System.out.println("Please specify the name of the key to use :"); 
			String nKey = si.next(); 


			//GET THE KEY FROM THE FILE

			FileInputStream fIn = new FileInputStream(nKey);

			byte buffer []  = new byte[8192];
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			int c;
			while ((c = fIn.read(buffer)) != -1) {
				os.write(buffer, 0, c);

			}
			byte key [] = Hex.decode(os.toByteArray());
			fIn.close();
			os.close();

			String keyHex = Hex.toHexString(key);
			System.out.println(keyHex);







			//CHOICE OF THE CRYPTED FILE FOR DECRYPTION

			System.out.println("Please specify the name of the crypted file for decrypt :");
			String nEncryptedFile = si.next(); //nEncryptedFile = name of the encrypted file
			System.out.println("Your will decrypt the file named " + nEncryptedFile);


			//GET THE CRYPTED FILE CONTENT
			FileInputStream fIn2 = new FileInputStream(nEncryptedFile);



			byte buffer2 []  = new byte[8192];
			ByteArrayOutputStream os2 = new ByteArrayOutputStream();
			int c2;
			while ((c2 = fIn2.read(buffer2)) != -1) {
				os2.write(buffer2, 0, c2);

			}
			byte fileToDecrypt [] = os2.toByteArray();
			os2.close();
			fIn2.close();

			//GET THE IV AND THE DATA FROM THE FILE
			byte IV [] = Arrays.copyOfRange(fileToDecrypt, 0, 24);//take the first 24 bytes of the encrypted file as it represent the IV
			fileToDecrypt = Arrays.copyOfRange(fileToDecrypt, 24, fileToDecrypt.length);//take the left bytes as it represent the file data to be decrypted

			String fileToDecryptHex = Hex.toHexString(fileToDecrypt);


			System.out.println("The hex value of the file to decrypt is :"+fileToDecryptHex);

			//CIPHER CONSTRUCTION FOR DECRYPTION

			byte[] ciphertext = fileToDecrypt;
			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RijndaelEngine(192)), new X923Padding()); 
			CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), IV); 
			cipher.init(false, ivAndKey); //false for decryption
			System.out.println("The decrypted hex is :" + Hex.toHexString(cipherData(cipher, ciphertext)));
			byte [] decrypted = cipherData(cipher,ciphertext);
			System.out.println("The decrypted text is :" + new String(decrypted));
			System.out.println("Please specify the name of the decryted file for storage (don't forget to add the extension to precise if it's a .txt or .png) :");
			String nDecryptedFile = si.next();
			System.out.println("The name of the decrypted file is " + nDecryptedFile);
			
			//STORAGE OF THE DECRYPTED FILE

			try {
				File file = new File(nDecryptedFile);
				if(!file.exists()) {
					file.createNewFile();
				}
				BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(file));
				fileOut.write(decrypted);

				fileOut.close();
			}
			catch(Exception e) {
				e.printStackTrace();
			}

		} catch (InvalidCipherTextException e) { 
			throw new RuntimeException(e); 
		} catch (FileNotFoundException e1) {

			e1.printStackTrace();
		} catch (IOException e1) {

			e1.printStackTrace();
		} 
	} 

	private static byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws InvalidCipherTextException 
	{ 
		int getSize = cipher.getOutputSize(data.length); 
		byte[] outBuffer = new byte[getSize]; 
		int length1 = cipher.processBytes(data, 0, data.length, outBuffer, 0); 
		int length2 = cipher.doFinal(outBuffer, length1); 
		int actualLength = length1 + length2; 
		byte[] cipherArray = new byte[actualLength]; 
		for (int x = 0; x < actualLength; x++) { 
			cipherArray[x] = outBuffer[x]; 
		} 
		return cipherArray; 
	} 


	static void keyGenerator() {


		int keyLength = 256;
		Scanner si = new Scanner(System.in);

		//KEY NAME SELECTION

		System.out.println("Please specify the name of the key :");
		String nKey = si.nextLine(); 
		System.out.println("Your key is will be stored in a file named :" + nKey);

		//KEY GENERATION
		KeyGenerationParameters param = new KeyGenerationParameters(new SecureRandom(),keyLength);
		CipherKeyGenerator keyGen = new CipherKeyGenerator();
		keyGen.init(param);
		byte[] keyByte = keyGen.generateKey();
		String keyHex = Hex.toHexString(keyByte);
		System.out.println("Your key is : " + keyHex);

		//STORAGE OF THE KEY 


		try {
			File file = new File(nKey);
			if(!file.exists()) {
				file.createNewFile();
			}
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
			writer.write(keyHex); 
			writer.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}


	}


}
