package seguridad_tp2;


import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

/**
* Clase que implementa el comportamiento necesario para generar y gestionar pareja de claves empleando algoritmo RSA
* @author Seg Red Ser
* @version 1.0
*/
public class GestionClaves {
		/**
		 * Genera pareja de claves empleando el algoritmo RSA
		 * @param e: BigInteger con el valor para el exponente
		 * @param tamClave: entero con valor para el tamaño en bits de la clave
		 * @return AsymmetricCipherKeyPair: con el par de claves.
		 */
		public static AsymmetricCipherKeyPair generarClaves (BigInteger e, int tamClave) {
			
			AsymmetricCipherKeyPair claves = null;
			
			RSAKeyPairGenerator generador = new RSAKeyPairGenerator ();
			RSAKeyGenerationParameters params = new RSAKeyGenerationParameters (e, new SecureRandom(), tamClave, 80);
			generador.init(params);
			
			claves = generador.generateKeyPair();
		 
			return claves;
			
		}
		/**
		 * Devuelve el valor de la clave privada en formato PKCS8. 
		 * @param clave: clave privada (AsymmetricKeyParameter)
		 * @return PrivateKeyInfo: la clave privada en formato PKCS8.
		 * @throws IOException 
		 */
		public static PrivateKeyInfo getClavePrivadaPKCS8 (AsymmetricKeyParameter clave) throws IOException {
			PrivateKeyInfo claveFinal = null;
			claveFinal = PrivateKeyInfoFactory.createPrivateKeyInfo(clave);
			
			return claveFinal;
		}
		
		/**
		 * Devuelve el valor de la clave publica en formato SPKI. 
		 * @param clave: clave publica (AsymmetricKeyParameter)
		 * @return SubjectPublicKeyInfo: la clave publica en formato SPKI.
		 * @throws IOException 
		 */
		public static SubjectPublicKeyInfo getClavePublicaSPKI (AsymmetricKeyParameter clave) throws IOException {
			
			SubjectPublicKeyInfo claveFinal = null;		
			
			claveFinal = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(clave);
			
			return claveFinal;
		}
		/**
		 * Devuelve el valor de la clave publica en formato RSAKeyParameters. 
		 * @param clave: clave publica (SubjectPublicKeyInfo)
		 * @return RSAKeyParameters: la clave publica en formato RSAKeyParameters.
		 * @throws IOException 
		 */
		public static RSAKeyParameters getClavePublicaMotor (SubjectPublicKeyInfo clave) throws IOException {
			
			RSAKeyParameters claveFinal = null;
						
			claveFinal = (RSAKeyParameters) PublicKeyFactory.createKey(clave);
			
			return claveFinal;
		}
		
		/**
		 * Devuelve el valor de la clave privada en formato RSAKeyParameters. 
		 * @param clave: clave privada (PrivateKeyInfo)
		 * @return RSAKeyParameters: la clave privada en formato RSAKeyParameters.
		 * @throws IOException 
		 */
		public RSAKeyParameters getClavePrivadaMotor (PrivateKeyInfo clave) throws IOException {
			
			RSAKeyParameters claveFinal = null;
			
			claveFinal = (RSAKeyParameters) PrivateKeyFactory.createKey(clave);
			
			return claveFinal;
		}
		
}
