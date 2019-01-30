import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.json.JSONObject;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.security.Principal;
import java.security.KeyStore.PrivateKeyEntry;

class Client {

	String name;
	int id;
	PublicKey pub;

	public Client(String name, int id, PublicKey pub) {
		this.name = name;
		this.id = id;
		this.pub = pub;
	}

}

public class AuctionManager {
	
	private static int counter = 0;
	private static int instcounter = 0;
	static List<Client> clients = new ArrayList<Client>();
	private static PublicKey publicKey = null;
	private static PrivateKey privateKey = null;
	private static SecretKey secKey = null;
	private static PublicKey repositoryPublicKey = null;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws KeyStoreException, UnrecoverableKeyException, UnrecoverableEntryException, CertificateException, IOException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		//readCert();
		//readKey();
		//idk();
		
		KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream("certs/man.p12"), "".toCharArray());
		Enumeration e = p12.aliases();
		System.out.println(e);
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            X509Certificate c = (X509Certificate) p12.getCertificate(alias);
            Principal subject = c.getSubjectDN();
            String subjectArray[] = subject.toString().split(",");
            for (String s : subjectArray) {
                String[] str = s.trim().split("=");
                String key = str[0];
                String value = str[1];
                System.out.println(key + " - " + value);
            }
		}
		
		char[] password="".toCharArray();
		String alias = "1";
		PrivateKey privateKey1 = (PrivateKey) p12.getKey(alias, password);
		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) p12.getEntry(alias, new KeyStore.PasswordProtection(password));
		System.out.println(encoder.encodeToString(privateKey1.getEncoded()));

		//Generate public and private keys
		generateKeys();	
		
		/*Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
		dsa.initSign(privateKey);
		FileInputStream fis = new FileInputStream(args[0]);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
			dsa.update(buffer, 0, len);
		};
		bufin.close();
		byte[] realSig = dsa.sign();

		/* save the signature in a file */
		/*FileOutputStream sigfos = new FileOutputStream("sig");
		sigfos.write(realSig);
		sigfos.close();

		/* save the public key in a file */
		/*byte[] key = publicKey.getEncoded();
		FileOutputStream keyfos = new FileOutputStream("manepk");
		keyfos.write(key);
		keyfos.close();*/

		//Send public key to repository
		DatagramSocket ds = new DatagramSocket(8000);
		JSONObject data = new JSONObject();
		InetAddress ia = InetAddress.getLocalHost();
		data.put("action", "serverconnection");
		String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		data.put("manpubkey", encodedKey);
		byte[] b1 = data.toString().getBytes();
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 9000);
		ds.send(dp1);		

		while(true) {
			byte[] b = new byte[1024];
			DatagramPacket dp = new DatagramPacket(b, b.length);
			ds.receive(dp);
			String line = new String(dp.getData());
			JSONObject jsonObject = new JSONObject(line);
			readCommand(jsonObject, dp, ds);
			instcounter++;
			
			//Renew Keys
			if(instcounter == 10) {
				generateKeys();
				instcounter = 0;
			}
		}
	}

	static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		//Receive repository's public key
		if(jsonObject.get("action").equals("serverconnection")) {
			repositoryPublicKey = getKey(jsonObject.getString("reppubkey"));
			System.out.println("Servers are connected successfuly");
		}
		
		//Client connection
		if(jsonObject.get("action").equals("newclient")) {
			//Add new client to ArrayList
			counter++;
			PublicKey clientKey = getKey(jsonObject.getString("clientkey"));
			Client c = new Client(jsonObject.getString("name"), counter, clientKey);
			clients.add(c);

			System.out.println(jsonObject.getString("name") + " connected successfuly");

			//Give client its new id and manager's public key
			JSONObject data = new JSONObject();
			InetAddress ia = InetAddress.getLocalHost();
			data.put("clientid", counter);
			String manpubkey = encoder.encodeToString(publicKey.getEncoded());
			data.put("manpubkey", manpubkey);
			byte[] b1 = data.toString().getBytes();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//Create a new auction
		if(jsonObject.get("action").equals("create")) {
			//Missing: process this new auction before sending to repository

			//Send data to repository
			System.out.println(jsonObject.toString());
			DatagramSocket ds1 = new DatagramSocket();
			InetAddress ia = InetAddress.getLocalHost();
			byte[] b = jsonObject.toString().getBytes();
			DatagramPacket dp1 = new DatagramPacket(b, b.length, ia, 9000);
			ds1.send(dp1);
		}
		
		//New bid
		if(jsonObject.get("action").equals("bid")) {
			//Missing: signature for receipt

			BufferedWriter writer = new BufferedWriter(new FileWriter("Receipts/client" + jsonObject.getInt("creatorid") + ".txt", true));
			writer.append(jsonObject.toString() + "\n");
			writer.close();
		}
	}

	static void generateKeys() throws NoSuchAlgorithmException {
		//AES - Symmetric Key		
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(128); // The AES key size in number of bits
		secKey = generator.generateKey();

		//RSA - Public and Private Keys
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		publicKey = kp.getPublic();
		privateKey = kp.getPrivate();

		
	}
	
	//Cipher with symmetric key
	static byte[] cipherAES(byte[] in) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
		return aesCipher.doFinal(in);
	}
	
	//Cipher with public key
	static byte[] cipherRSA(byte[] in, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(in);
	}
	
	//Decipher with private key
	static byte[] decipherRSA(byte[] in, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
	    cipher.init(Cipher.DECRYPT_MODE, key);  
	    return cipher.doFinal(in);
	}
	
	//Method to generate key given byte array
	static PublicKey getKey(String key) {
	    try{
	        byte[] byteKey = decoder.decode(key.getBytes());
	        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        return kf.generatePublic(X509publicKey);
	    }
	    catch(Exception e){
	        e.printStackTrace();
	    }
	    return null;
	}

	static Certificate readCert() {
		try {
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			InputStream is = Files.newInputStream(Paths.get("certs/man.crt"));
			X509Certificate crt = (X509Certificate) fact.generateCertificate(is);
			return crt;
		} catch(Exception e) { 
			System.out.println("Error while reading certificate: " + e);
			return null;
		}
	}

	static PrivateKey readKey() {
		try {
			Path p = Paths.get("certs/man.pem");
			byte[] bytes = Files.readAllBytes(p);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
			return kf.generatePrivate(ks);
		} catch(Exception e) {
			System.out.println("Error while reading key: " + e);
			return null;
		}
	}

	static void idk() {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream("certs/man.p12"), null);
			Key pvtkey = ks.getKey("private", null);
			System.out.println(pvtkey.getEncoded());
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
