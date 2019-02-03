import java.util.Enumeration;
import java.security.*;
import java.security.cert.Certificate;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.security.cert.*;

class SmartCard {
    String f = "CitizenCard.cfg";
    Provider p;
    KeyStore ks;
    boolean provider = false;

    SmartCard () {
        provider = addProvider();
    }

    boolean
    addProvider(){
        try{
            p = new sun.security.pkcs11.SunPKCS11(f);
            Security.addProvider( p );
            //System.out.println("Addedd provider");
            ks = KeyStore.getInstance( "PKCS11", "SunPKCS11-PTeID");
            ks.load(null, null);
            provider = true;
            return provider;
        }catch(Exception e){
            System.err.println("Error in CC Add Provider"+e);
            provider = false;
            return provider;
        }
    }

    String
    getCertString(){
        try{
            String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
            String END_CERT = "-----END CERTIFICATE-----";
            String LINE_SEPARATOR = System.getProperty("line.separator");
            Base64.Encoder encoder = Base64.getEncoder();
            X509Certificate cac = (X509Certificate) ks.getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
            byte[] buffer = cac.getEncoded();
            return BEGIN_CERT+LINE_SEPARATOR+new String(encoder.encode(buffer))+LINE_SEPARATOR+END_CERT;
        }catch (Exception e){
            System.err.println("Error Getting Client Cert String : " + e);
            return null;
        }
    }



    String
    sign(String toSign){
        try{
            Signature sign = Signature.getInstance("SHA256withRSA", "SunPKCS11-PTeID");
            PrivateKey privKey = (PrivateKey) ks.getKey("CITIZEN AUTHENTICATION CERTIFICATE", null);
            sign.initSign(privKey);
            sign.update(toSign.getBytes());
            byte[] signature = sign.sign();
            return Base64.getEncoder().encodeToString(signature);
        }catch (Exception e){
            System.err.println("Error Signing with CC : " + e);
            return null;
        }
    }

    boolean
    verifySign(String toVerify, String signature, PublicKey pubk){
        try{
            Signature verif = Signature.getInstance("SHA256withRSA");
            verif.initVerify(pubk);
            verif.update(toVerify.getBytes());
            boolean verification = verif.verify(Base64.getDecoder().decode(signature));
            return verification;
        }catch (Exception e){
            System.err.println("Error Verifying Signature with CC : " + e);
            return false;
        }
   }

    PublicKey
    getCertKey(){
        try{
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            X509Certificate cer = (X509Certificate) fact.generateCertificate(
                    new ByteArrayInputStream(getCertString().getBytes()));
            return cer.getPublicKey();
        }catch(Exception e){
            System.err.print("Error geting User pubk");
            System.exit(1);
        }
        return null;
    }
}