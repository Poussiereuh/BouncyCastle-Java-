package seguridad_tp2;


import java.util.Calendar;
import java.util.GregorianCalendar;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.cert.CertException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Scanner;


public class Principal {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, OperatorCreationException, PKCSException, CertException {

		Usuario u =new Usuario();
		
		CA ca=new CA();
		
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		String fichero;
		
		//Para trabajo como usuario
		String ficheroClavePrivada;
		String ficheroClavePublica;
		AsymmetricCipherKeyPair parClavesUsu=null;  //MARISA
		
		//Para trabajo como CA
	
		String ficheroCA=null;
		String ficheroCertUsu=null;
		
		do {
			Date fecha=new Date(System.currentTimeMillis());
			System.out.println("Fecha actual...:"+fecha.toString());
			
			Date fechaInicioCert=GregorianCalendar.getInstance().getTime();
			System.out.println("FechaInicioCert...:"+fechaInicioCert.toString());
			
			Calendar c1 = GregorianCalendar.getInstance();
			c1.add(Calendar.YEAR, 4);
		    Date fechaFinCert=c1.getTime();
		    System.out.println("fechaFinCert...:"+fechaFinCert.toString());

		    System.out.println("¿Con qué rol desea trabajar?");
			System.out.println("1. Trabajar como usuario.");
			System.out.println("2. Trabajar como Autoridad de Certificación.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opción para trabajar como USUARIO:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar pareja de claves en formato PEM.");
						System.out.println("2. Crear petición de certificación.");
						System.out.println("3. Verificar certificado externo.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1://Generar pareja de claves.
								System.out.println("OPCIÓN GENERA PAREJA DE CLAVES");
								System.out.println("Escriba el nombre del fichero que contendrá la clave privada:");
								ficheroClavePrivada = sc.next();
								System.out.println("Escriba el nombre del fichero que contendrá la clave publica:");
								ficheroClavePublica = sc.next();
								//COMPLETAR ESTUDIANTE
								parClavesUsu = Usuario.generarClaves(ficheroClavePrivada, ficheroClavePublica);
								
							break;
							case 2://Crear petición de certificado.
								
								if (parClavesUsu==null)
									     System.out.println("El usuario debe tener un par de claves");
								else
								{
									System.out.println("Escriba el nombre del fichero que contendrá la petición de certificación:");
									fichero= sc.next();
									
									//COMPLETAR ESTUDIANTE
									
									Usuario.crearPetCertificado(parClavesUsu, fichero);
								
							    }
								
							break;
							case 3://Verificar certificado externo.
							      
							    	   System.out.println("Escriba el nombre del fichero que contiene el certificado del usuario:");
									   fichero = sc.next();
							    	   System.out.println("Escriba el nombre del fichero que contiene el certificado de la CA:");
									   ficheroCA = sc.next();
									 //COMPLETAR ESTUDIANTE  
									   boolean check = Usuario.verificarCertificadoExterno(ficheroCA, fichero);
									   if (check)
										   System.out.println("Validacion del certificado");
									   else
										   System.out.println("Error");
				        
								break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opción para trabajar como CA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar pareja de claves y el certificado autofirmado nuevos.");
						System.out.println("2. Cargar pareja de claves.");
						System.out.println("3. Certificar una petición de certificación.");
					
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1://Generar pareja de claves, el certificado X509 y guardar en ficheros.
									
									ca.inicializar(false);
								    System.out.println("Claves y certificados X509 GENERADOS");
								    System.out.println("Se han guardado en " + CA.NOMBRE_FICHERO_CRT + ", " + CA.NOMBRE_FICHERO_CLAVES_PUBLICA + ".txt" + ", " + CA.NOMBRE_FICHERO_CLAVES_PRIVADA + ".txt");									
								
							break;
							case 2://Cargar de ficheros pareja de claves
									
									ca.inicializar(true);
									System.out.println("Claves CARGADAS");
									System.out.println("Se han cargado de " + CA.NOMBRE_FICHERO_CLAVES_PUBLICA + ".txt" + ", " + CA.NOMBRE_FICHERO_CLAVES_PRIVADA + ".txt");								
								
							break;
							case 3://Certificar una petición
								    System.out.println("Escriba el nombre del fichero que contiene la petición de certificación del usuario:");
								    fichero = sc.next();
									System.out.println("Escriba el nombre del fichero que contendrá el certificado emitido por la CA para el usuario:");
								    ficheroCertUsu = sc.next();
								    //COMPLETAR ESTUDIANTE
								    boolean check = CA.certificarPeticion(fichero, ficheroCertUsu);
								    if (check)
								    	System.out.println("Creation del certificado");
								    else
								    	System.out.println("Error durante la creation");
								    
								    
							break;							
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
     
		sc.close();         
	}	
}
