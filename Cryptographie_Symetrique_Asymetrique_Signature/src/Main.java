/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author Profesores de la asignatura
 * @version 1.0
 */

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;



public class Main {


	
	public static void main (String [ ] args) throws IOException, NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException {
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		

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
							break;
							case 3:
								Symetric.decryptWithRijndaelCBC();
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Select an option:");
						System.out.println("0. Back.");
						System.out.println("1. Generate key.");
						System.out.println("2. Encrypt.");
						System.out.println("3. Decrypt.");
						System.out.println("4. Digital signature");
						System.out.println("5. Siganture verification.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								Asymetric.generateKey();
							break;
							case 2:
								Asymetric.encryptWithRSA();
							break;
							case 3:
								Asymetric.decryptWithRSA();
							break;
							case 4:
								Signature.sign();
							break;
							case 5:
								Signature.verify();
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}