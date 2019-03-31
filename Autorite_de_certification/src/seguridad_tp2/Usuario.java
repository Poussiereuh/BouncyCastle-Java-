package seguridad_tp2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequest;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;
/**
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificación
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {
	
	/**
	 * Método privado que genera una petición de certificado en formato PKCS10.
	 * @param nombreUsuario: X500Name
	 * @param clavePub: RSAKeyParameters
	 * @param clavePriv: RSAKeyParameters
	 * @throws OperatorCreationException 
	 * @throws PKCSException 
	 * @return PKCS10CertificationRequest: Petición de certificación en formato PKCS10.
	 */
	private static PKCS10CertificationRequest crearPeticionPKCS10 (X500Name nombreUsuario, RSAKeyParameters clavePub, RSAKeyParameters clavePriv)  throws OperatorCreationException, IOException{
		
		//IMPLEMENTAR ESTUDIANTE
		
		// Preparar la firma del certificado
		
		PKCS10CertificationRequest cr;
		
		DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();//Firma
		DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();//Resumen
			    
		AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
		AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
			            
		BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		
		// generar el builder
		
		PKCS10CertificationRequestBuilder pkcs_certification_request_builder = new PKCS10CertificationRequestBuilder(nombreUsuario, GestionClaves.getClavePublicaSPKI(clavePub));

		cr = pkcs_certification_request_builder.build(csBuilder.build(clavePriv));
		
		return cr;
		
		
	}
	
	/**
	 * Método privado que verifica la firma de un certificado de entidad.
	 * @param certificadoEntidad: X509CertificateHolder 
	 * @param certificadoCA: X509CertificateHolder 
	 * @throws OperatorCreationException 
	 * @throws CertException 
	 * @throws IOException 
	 * @return boolean: true si verificación OK, false en caso contrario.
	 */
	private static boolean verificarFirmaCertificado (X509CertificateHolder certificadoEntidad, X509CertificateHolder certificadoCA) throws OperatorCreationException, CertException, IOException{
		//IMPLEMENTAR ESTUDIANTE
		
		//Reconstrucción de clave pública del CA
		SubjectPublicKeyInfo clave_pub_info = certificadoCA.getSubjectPublicKeyInfo();
		RSAKeyParameters clave_pub_ca = GestionClaves.getClavePublicaMotor(clave_pub_info);
		
		//3
		ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(clave_pub_ca);
		
		if (certificadoEntidad.isSignatureValid(contentVerifierProvider))
			return true;
		else
			return false;
		
		
	}
	
	
	/**
	 * Método que genera y devuelve las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardará la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardará la clave publica en formato PEM
	 * @return 
     * @throws IOException 	
	 */
	public static AsymmetricCipherKeyPair generarClaves (String fichClavePrivada, String fichClavePublica) throws IOException{
		//IMPLEMENTAR ESTUDIANTE
		
		AsymmetricCipherKeyPair claves = GestionClaves.generarClaves(BigInteger.valueOf(65537), 1024);
		SubjectPublicKeyInfo clave_SPKI = GestionClaves.getClavePublicaSPKI(claves.getPublic());
		PrivateKeyInfo clave_PKCS8 = GestionClaves.getClavePrivadaPKCS8(claves.getPrivate());
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clave_SPKI.getEncoded(), fichClavePublica);
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clave_PKCS8.getEncoded(), fichClavePrivada);
		
		return claves;
    }
	
	
	/**
	 * Método que genera una petición de certificado en formato PEM,almacenando esta petición en un fichero.
	 * @param parClaves: AsymmetricCipherKeyPair
	 * @param fichPeticion: String con el nombre del fichero donde se guardará la petición de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public static void crearPetCertificado(AsymmetricCipherKeyPair parClaves, String fichPeticion ) throws OperatorCreationException, IOException {
		
		//IMPLEMENTAR ESTUDIANTE
		X500Name subject = new X500Name("C=ES, O=DTE, CN=USUARIO");
		
		PKCS10CertificationRequest peticion = crearPeticionPKCS10(subject, (RSAKeyParameters) parClaves.getPublic(), (RSAKeyParameters) parClaves.getPrivate());
		
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS10_PEM_HEADER, peticion.getEncoded(), fichPeticion);
		
	}
	
	
	/**
	 * Método que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificación OK, false en caso contrario.
	 */
    public static boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, CertException, FileNotFoundException, IOException {
    	//IMPLEMENTAR ESTUDIANTE
    	X509CertificateHolder certUsuario = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoUsu);
    	Date date = GregorianCalendar.getInstance().getTime();
    	if ( date.before(certUsuario.getNotBefore()) || date.after(certUsuario.getNotAfter()) )
    		return false;
    	else
    	{
    		//1
    		X509CertificateHolder certCA = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoCA);
    		Boolean result = Usuario.verificarFirmaCertificado(certUsuario, certCA);
    		return result;
    	}
    	
		
	}	
}
