package seg_as;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;



public class Main {


	
	public static void main (String [ ] args) throws Exception {
		int menu1;
		int menu2;
		int len = 256;
		String s = "";
		String nF ="";
		String nKey = "";
		String keyHex = "";
		Scanner sc = new Scanner(System.in);
		Scanner si = new Scanner(System.in);
		byte[] IV = new byte[24];
		SecureRandom.getInstance("SHA1PRNG").nextBytes(IV);
		String IVinHex = Hex.toHexString(IV);
		System.out.println("the generated IV is :" +IVinHex);

		/* Déclaration des variables */
	
		
		
		do {
			System.out.println("Which type of crytpo do you wanna use ?");
			System.out.println("1. Symmetric.");
			System.out.println("2. Asymmetric.");
			System.out.println("3. Exit.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Select an option :");
						System.out.println("0. Back.");
						System.out.println("1. Generate a key.");
						System.out.println("2. Encrypt.");
						System.out.println("3. Decrypt.");
						menu2 = sc.nextInt();
				
						
						switch(menu2){
							case 1:
								Symetric.keyGenerator();
							break;
							
							case 2:
								Symetric.encryptWithRijndaelCBC();
//								
//								// CHOICE OF KEY TO USE FOR ENCRYPTION
//								System.out.println("Please specify the name of the key to use for encryption :"); 
//								nKey = si.nextLine(); 
//								
//								
//								//RECUPERATION DE LA CLEF
//								BufferedReader br = null;
//								FileReader fr = null;
//
//								try {
//
//									fr = new FileReader(nKey);
//									br = new BufferedReader(fr);
//
//									String sCurrentLine;
//
//									keyHex = sCurrentLine = br.readLine();
//
//								} catch (IOException e) {
//
//									e.printStackTrace();
//								}
//								
//									byte [] KeyandIVByte = Hex.decode(keyHex);
//									byte [] KeyByte = null;
//									byte [] IVByte = null;
//									System.arraycopy(KeyandIVByte, 24, KeyByte, 0, KeyandIVByte.length);
//									System.arraycopy(KeyandIVByte, 0, IVByte, 0, 24);
//
//									
//									// SELECTING THE ENCRYPTER FILE
//								System.out.println("Please specify the name of the file for encrypt :");
//								String file = si.nextLine(); //nClearFile = name of the clear file
//								System.out.println("You will encrypt th1e file named " + file);
//								
//								String content_file = Symetric.importFileContent(file);
//								
//								// Encryption
//								String content_file_hex = Symetric.str2Hex(content_file);
//								System.out.println("The hexa value of the file to encrypt is :"+content_file_hex);
//								
//								// ENCRYPTION AND STORAGE
//								Symetric.encryptWithRijndaenCBC(content_file.getBytes(), KeyByte, IVByte);
//								
//							
							break;
							case 3:
								
								Symetric.decryptWithRijndaelCBC();
//								// CHOICE OF KEY TO USE FOR ENCRYPTION
//								System.out.println("Please specify the name of the key to use :"); // the user enters the name of the key and therefore of the file where it is
//								nKey = si.nextLine(); // we enter the variable of the key in hexa 
//								
//								
//								
//								
//								
//								//RECUPERATION DE LA CLEF
//								BufferedReader br1 = null;
//								FileReader fr1 = null;
//
//								try {
//
//									fr1 = new FileReader(nKey);
//									br1 = new BufferedReader(fr1);
//
//									String sCurrentLine;
//
//									keyHex = sCurrentLine = br1.readLine();
//
//								} catch (IOException e) {
//
//									e.printStackTrace();
//								}
//								
//									byte [] KeyandIVByte1 = Hex.decode(keyHex);
//									byte [] KeyByte1 = null;
//									byte [] IVByte1 = null;
//									System.arraycopy(KeyandIVByte1, 24, KeyByte1, 0, KeyandIVByte1.length);
//									System.arraycopy(KeyandIVByte1, 0, IVByte1, 0, 24);
//								
//								
//								
//								
//								
//								
//								
//								// SPECIFY THE FILE NAME TO DECHIFFRER
//								
//								System.out.println("Please specify the name of the crypted file for encrypt :");
//								String nEncryptedFile = si.nextLine(); //nClearFile = name of the clear file
//								System.out.println("Your will decrypt the file named " + nEncryptedFile);
//								
//								
//								// RECOVERING THE DECRYPTER FILE
//								
//							    byte [] fileToDecrypt = Symetric.importFileContentByte(nEncryptedFile);
//	
//								
//								// DECRYPTING
//								Symetric.decryptWithRijndaelCBC(fileToDecrypt, KeyByte1, IVByte1);
//								

							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opcion para CRIPTOGRAFIA ASIMÉTRICA:");
						System.out.println("0. Back.");
						System.out.println("1. Generate key.");
						System.out.println("2. Encrypt.");
						System.out.println("3. Decrypt.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
						
				
						switch(menu2){
							case 1:
								
								 System.out.println("Enter the name of the file that will contain the private key (exponent/modulus) :");
								 String filePrivK = si.nextLine();
								 System.out.println("Enter the name of the file that will contain the public key (exponent/modulus) :");
								 String filePubK = si.nextLine();
								 
								//Keypair generation
								 System.out.println("Key Pair Generation started.");
								 AsymmetricCipherKeyPair keyPair = Asymetric.GenerateKeys();
								 RSAKeyParameters pri = (RSAKeyParameters)keyPair.getPrivate();
								 RSAKeyParameters pub = (RSAKeyParameters)keyPair.getPublic();
								 System.out.println("Key Pair Generation ended.");
								 
								 GuardarFormatoPEM.guardarClavesPEM(pub, pri); //write public and private key in pem format
								 
								 Asymetric.saveExponentModulus(pub.getModulus(), pub.getExponent(), filePubK); //save the exponent/modulus of the public key
								 Asymetric.saveExponentModulus(pri.getModulus(), pri.getExponent(), filePrivK);// save the exponent/modulus of the private key
							break;
							
							case 2:
								 System.out.println("Enter the name of the file that contains the text to encrypt:");
								 String fileToEncrypt = si.nextLine();
								 System.out.println("Enter the name of the file that contains public key: ");
								 String filePubK1 = si.nextLine();
								 System.out.println("Enter the name of the file that will contain the encrypted text: ");
								 String fileEncrypt = si.nextLine();
								 
								 //Regenerate Key with exponent/modulus
								 BigInteger modulus_exponant[] = Asymetric.importExponentModulus(filePubK1);
								 BigInteger modulus = modulus_exponant[0];
								 BigInteger exponant = modulus_exponant[1];
								 
								 RSAKeyParameters keyRege = new RSAKeyParameters(false, modulus, exponant);
								 
								 //Get content of the file
								 String plainMessage = Asymetric.importFileContent(fileToEncrypt);
								 System.out.println("Content of the file: "+plainMessage);
								 
								 //Encryption
								 System.out.println("Encryption started. ");
								 String encryptedMessage = Asymetric.Encrypt(plainMessage.getBytes("UTF-8"), keyRege);
								 System.out.println(encryptedMessage);
								 Asymetric.saveContent(fileEncrypt, encryptedMessage);
								 System.out.println("Encryption ended.");
								 
							break;
							case 3:
								 System.out.println("Enter the name of the file that contains the encrypted text: ");
								 String fileEncrypted = si.nextLine();
								 System.out.println("Enter the name of the file that contains private key: ");
								 String filePrivK1 = si.nextLine();
								 System.out.println("Enter the name of the file that will contain the decrypted message: ");
								 String fileDecrypted = si.nextLine();
								 
								 //import text encrypted
								 String textEncrypted = Asymetric.importFileContent(fileEncrypted);
								 
								 //regenerate private key
								 BigInteger modulus_exponant1[] = Asymetric.importExponentModulus(filePrivK1);
								 BigInteger modulus1 = modulus_exponant1[0];
								 BigInteger exponant1 = modulus_exponant1[1];
								 
								 RSAKeyParameters keyRege1 = new RSAKeyParameters(true, modulus1, exponant1); //true because privatekey
								 
								 System.out.println("Decryption started.");
								 System.out.println(textEncrypted);
								 String decryptedMessage = Asymetric.Decrypt(textEncrypted, keyRege1); //decrypt
								 System.out.println("Décrypted message: "+decryptedMessage);
								 Asymetric.saveContent(fileDecrypted, decryptedMessage);
								 System.out.println("--------------");
								 System.out.println("");
							break;
							case 4:
								// Choose the used key
								System.out.println("Please specify the name of the key to use for signing (ex: privatekey) :"); 
								nKey = si.nextLine();
								
								BigInteger Tablo[] = Asymetric.importExponentModulus(nKey);
								
								RSAKeyParameters keyRegesign = new RSAKeyParameters(true, Tablo[0], Tablo [1]);
								
								System.out.println("You key is :"+keyRegesign);
                                                                
                                                                // Choose the file to sign
                                System.out.println("Please specify the name of the file to sign (file in plaintext):"); 
								String nFile = si.nextLine();
                                                                // Read and store the key Hex value 
								 String plainMessage1 = Asymetric.importFileContent(nFile);
								 System.out.println("Content of the file: "+plainMessage1);
                                                                
                                 // Digest and encrypt the file
								 
								 
								 MessageDigest sha = MessageDigest.getInstance("SHA-256");
								 sha.update(plainMessage1.getBytes());
                                 byte[] digest = sha.digest();
                                 String encrypteMessageDigest = Asymetric.Encrypt(digest, keyRegesign);
                                 System.out.println(encrypteMessageDigest);
                                                                
                                 // Create and write the Digest Message
                                System.out.println("Please specify the name of the signed file :"); 
                                String signedfile = si.nextLine();
                                                               
                                Asymetric.saveContent(signedfile, encrypteMessageDigest);

							break;
							case 5:
								 // Choose the origin file
                                System.out.println("Please specify the name of the origin file (plaintext) :"); 
								nFile = si.nextLine();
								// Read and store the signed file content
								
								//MESSAGE CLAIR
								String plainMessage11 = Asymetric.importFileContent(nFile);
								System.out.println("Content of the file: "+plainMessage11);
								sha = MessageDigest.getInstance("SHA-256");
								sha.update(plainMessage11.getBytes());
								byte[] digestOrigin = sha.digest();
								
								
								// Choose the used key
								System.out.println("Please specify the name of the key to use for signing (ex: publickey):"); 
								nKey = si.nextLine();
								BigInteger Tablo1[] = Asymetric.importExponentModulus(nKey);
								RSAKeyParameters keyRegen = new RSAKeyParameters(false, Tablo1[0], Tablo1 [1]);
								
								System.out.println("You key is :"+keyRegen);
								
								
								// Choose the signed file
								System.out.println("Please specify the name of the signed file:"); 
								nFile = si.nextLine();
                                String cryptedmessage = Asymetric.importFileContent(nFile);
                                byte[] digestDownload = Asymetric.Decrypt(cryptedmessage, keyRegen).getBytes();
                                
								                           
                                boolean verify = Arrays.equals(digestOrigin,digestDownload);
                                
                                System.out.println(verify);
                                System.out.println(digestOrigin);
                                System.out.println(digestDownload);
                                
                                if(Arrays.equals(digestOrigin,digestDownload) == true){
                                    System.out.println("The signature is valid");
                                }
                                else {
                                	System.out.println("The signature is not valide");
                                }
                                
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}