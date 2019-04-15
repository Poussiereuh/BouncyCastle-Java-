import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


public class GuardarFormatoPEM {

	public final static String PKCS8KEY_PEM_HEADER = "PRIVATE KEY";
	public final static String PUBLICKEY_PEM_HEADER = "PUBLIC KEY";
		
	public static void guardarClavesPEM(AsymmetricKeyParameter clavePublica, AsymmetricKeyParameter clavePrivada){
		try{
		    SubjectPublicKeyInfo clavePublic = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(clavePublica);
	
			PemObject poPub = new PemObject (PUBLICKEY_PEM_HEADER, clavePublic.getEncoded());
			PemWriter pemWriterPublica = new PemWriter(new OutputStreamWriter(new FileOutputStream("PublicaPEM.txt")));
			try {
				pemWriterPublica.writeObject(poPub);
	    	} finally {
	    		pemWriterPublica.close();
	    	}
			
			
            PrivateKeyInfo clavePrivate = PrivateKeyInfoFactory.createPrivateKeyInfo(clavePrivada);;
            
            PemObject poPriv = new PemObject (PKCS8KEY_PEM_HEADER, clavePrivate.getEncoded());
            PemWriter pemWriterPrivada = new PemWriter(new OutputStreamWriter(new FileOutputStream("PrivadaPEM.txt")));
			try {
				pemWriterPrivada.writeObject(poPriv);
			} finally {
	    		pemWriterPrivada.close();
	    	}	    	
		}
		catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    					
	}
}