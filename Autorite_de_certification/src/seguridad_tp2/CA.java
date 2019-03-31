package seguridad_tp2;


import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Scanner;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import java.util.Date;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;

/**
* Esta clase implementa el comportamiento de una CA
* @author Seg Red Ser
* @version 1.0
*/
public class CA {
	
	private final X500Name nombreEmisor;
	private BigInteger numSerie;
	private final int a�osValidez; 
	
	
	public final static String NOMBRE_FICHERO_CRT = "CertificadoCA.crt";
	public final static String NOMBRE_FICHERO_CLAVES_PUBLICA = "CA-clave-publica";
	public final static String NOMBRE_FICHERO_CLAVES_PRIVADA = "CA-clave-privada";

	private static CA CA = new CA();
	
	private static RSAKeyParameters clavePrivadaCA = null;
	private static RSAKeyParameters clavePublicaCA = null;
	/**
	 * Constructor de la CA. 
	 * Inicializa atributos de la CA a valores por defecto
	 */
	public CA () {
		this.nombreEmisor = new X500Name ("C=ES, O=DTE, CN=CA");
		this.numSerie = BigInteger.valueOf(1);
		this.a�osValidez = 1;
	}
	
	 /**
	 * M�todo que inicializa la CA. Carga o genera la parejas de claves de la CA y el certificado autofirmado de la CA.
	
	 * @param cargar:boolean. Si es true, carga los datos de ficheros existentes. Si es false, genera datos nuevos y los guarda en ficheros para futuras ocasiones. 
	 * @throws OperatorCreationException
	 * @throws IOException 
	 */
	
	public void inicializar (boolean cargar) throws OperatorCreationException, IOException{
		//IMPLEMENTAR ESTUDIANTE

		if (cargar) {
			// Cargar la pareja de claves del fichero indicado por NOMBRE_FICHERO_CLAVES
			clavePublicaCA = (RSAKeyParameters) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES_PUBLICA);
			clavePrivadaCA = (RSAKeyParameters) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES_PRIVADA);
			
		}
		else {
			// Generar una pareja de claves nueva y guardarla en el fichero indicado por NOMBRE_FICHERO_CLAVES
			AsymmetricCipherKeyPair claves = GestionClaves.generarClaves(BigInteger.valueOf(65537), 1024);
			clavePrivadaCA = (RSAKeyParameters) claves.getPrivate();
			clavePublicaCA = (RSAKeyParameters) claves.getPublic();
			SubjectPublicKeyInfo clave_SPKI = GestionClaves.getClavePublicaSPKI(clavePublicaCA);
			PrivateKeyInfo clave_PKCS8 = GestionClaves.getClavePrivadaPKCS8(clavePrivadaCA);
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clave_SPKI.getEncoded(), NOMBRE_FICHERO_CLAVES_PUBLICA);
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clave_PKCS8.getEncoded(), NOMBRE_FICHERO_CLAVES_PRIVADA);
			
			// Generar tambi�n un certificado y guardarlo en el fichero indicado por NOMBRE_FICHERO_CRT
			Date start = GregorianCalendar.getInstance().getTime();
			Calendar c1 = GregorianCalendar.getInstance();
			c1.add(Calendar.YEAR, 4);
		    Date end = c1.getTime();
		    
			X509v3CertificateBuilder CertB = new X509v3CertificateBuilder(this.nombreEmisor, this.numSerie, start, end, this.nombreEmisor, clave_SPKI);
			
			//Firma
			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();//Firma
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();//Resumen
			AlgorithmIdentifier sigAlgId =sigAlgFinder.find("SHA256withRSA");
			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
			BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
			
			//Certificate
			X509CertificateHolder holder = CertB.build(csBuilder.build(clavePrivadaCA));
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.CERTIFICATE_PEM_HEADER, holder.getEncoded(), NOMBRE_FICHERO_CRT);
			
		}
	}
	
	/**
	 * M�todo que genera el certificado de un usuario a partir de una petici�n de certificaci�n
	 * @param ficheroPeticion:String. Par�metro con la petici�n de certificaci�n
	 * @param ficheroCertUsu:String. Par�metro con el nombre del fichero en el que se guardar� el certificado del usuario
	 * @throws IOException 
	 * @throws PKCSException 
	 * @throws OperatorCreationException
	 */
	public static boolean certificarPeticion(String ficheroPeticion, String ficheroCertUsu) throws IOException, OperatorCreationException, PKCSException{
		//IMPLEMENTAR ESTUDIANTE
		
		//Verificar que la CA tiene sus claves
		if (clavePublicaCA == null || clavePrivadaCA == null) {
			System.out.println("El CA debe tener sus claves");
			return false;
		}
			
		
		else
		{
			// Leer el fichero que contiene la petici�n 
			PKCS10CertificationRequest peticion = (PKCS10CertificationRequest) GestionObjetosPEM.leerObjetoPEM(ficheroPeticion);
			//Generaci�n de la clave de usuario 
			SubjectPublicKeyInfo clave_SubjectPublicKeyInfo = peticion.getSubjectPublicKeyInfo();
			RSAKeyParameters clave_pub_user = GestionClaves.getClavePublicaMotor(clave_SubjectPublicKeyInfo);
			
			if (CA.verificaFirmaDePeticion(peticion, clave_pub_user)) { //Si la firma es v�lida
				
				X509CertificateHolder certificado = CA.crearCertificado(peticion); //crear Certificado y registro
				GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.CERTIFICATE_PEM_HEADER, certificado.getEncoded(),ficheroCertUsu);
				
				return true;
			}
			
			else {
				System.out.println("Firma invalido");
				return false;
			}

		}
	   
	}
	
	/**
	 * M�todo privado que comprueba la validez de la firma de una petici�n de certificaci�n.
	 * Esta verificaci�n es necesaria llevarla a cabo para crear el Certificado de usuario a partir de la petici�n de certificaci�n
	 * @param pet:PKCS10CertificationRequest. Par�metro con la petici�n de certificaci�n en formato PKCS10
	 * @param clavePub:RSAKeyParameters. Par�metro con la clave p�blica
	 * @throws PKCSException 
	 * @throws OperatorCreationException
	 * @return boolean: true si verificaci�n firma OK, false en caso contrario.
	 */	
	private static boolean verificaFirmaDePeticion (PKCS10CertificationRequest pet, RSAKeyParameters clavePub) throws OperatorCreationException, PKCSException{
		//IMPLEMENTAR ESTUDIANTE
		
		// Generar el objecto para verificar la firma de la peticion
		ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(clavePub);
		
		if (pet.isSignatureValid(contentVerifierProvider)) // Verificar la firma de la peticion
			return true;
		else
			return false;
		
		
		
		
	}
	
	/**
	 * M�todo privado que genera el certificado de un usuario a partir de una petici�n de certificaci�n
	 * Este m�todo es necesario emplearlo para Certificar una Petici�n
	 * @param pet:PKCS10CertificationRequest. Par�metro con la petici�n de certificaci�n en formato PKCS10
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 * @throws PKCSException 
	 * @result X509CertificateHolder: certificado X.509
	 */
	private static X509CertificateHolder crearCertificado (PKCS10CertificationRequest pet) throws OperatorCreationException, PKCSException, IOException{
		//IMPLEMENTAR ALUMNO
		
		// Definici�n de la fecha de fin y de inicio
		Date start = GregorianCalendar.getInstance().getTime();
		Calendar c1 = GregorianCalendar.getInstance();
		c1.add(Calendar.YEAR, 1);
		Date end = c1.getTime();
		
		X500Name UserName = pet.getSubject();
		
		SubjectPublicKeyInfo clave_SubjectPublicKeyInfo = pet.getSubjectPublicKeyInfo();
		RSAKeyParameters clave_pub_user = GestionClaves.getClavePublicaMotor(clave_SubjectPublicKeyInfo);
		
        // Generar el builder del certificado
        X509v3CertificateBuilder CertificadoUser = new X509v3CertificateBuilder(CA.nombreEmisor, BigInteger.valueOf(System.currentTimeMillis()), start, end, UserName, clave_SubjectPublicKeyInfo);
        
        // Preparar la firma del certificado
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
        BcRSAContentSignerBuilder csb = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
        
        return CertificadoUser.build(csb.build(clavePrivadaCA));
	}
	
	/** COMPLETAR ESTUDIANTE M�TODO PRIVADO cargarClaves
	 * M�todo que inicializa la clave p�blica y privada de la CA con los datos que hay en ficheros con las claves. 
	 * @throws IOException 
	 */
	
	/** COMPLETAR ESTUDIANTE M�TODO PRIVADO guardarClaves
	 * M�todo que guarda la clave p�blica y privada de la CA en ficheros con las claves. 
	 * @throws IOException 
	 */
	
}
