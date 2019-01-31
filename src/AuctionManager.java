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
import javax.crypto.spec.SecretKeySpec;

class Client {

	int id;
	SecretKey sessionkey;
	String name;
	String s;

	public Client(SecretKey sessionkey, String name, String s, int id) {
		this.sessionkey = sessionkey;
		this.name = name;
		this.s = s;
		this.id = id;
	}

}

public class AuctionManager {
	
	private static int counter = 0;
	private static int instcounter = 0;
	private static String path = "certs/man.p12";
	private static Principal issuerman = null;
	static List<Client> clients = new ArrayList<Client>();
	private static PublicKey publicKey = null;
	private static PrivateKey privateKey = null;
	private static SecretKey secKey = null;
	private static PublicKey repositoryPublicKey = null;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws KeyStoreException, UnrecoverableKeyException, UnrecoverableEntryException, CertificateException, IOException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		generateKeys();	
		
		//read own certificate
		KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream(path), "".toCharArray());
		Enumeration e = p12.aliases();
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            X509Certificate c = (X509Certificate) p12.getCertificate(alias);
            issuerman = c.getIssuerDN();
		}
		
		//Send certificate path to repository
		DatagramSocket ds = new DatagramSocket(8000);
		JSONObject data = new JSONObject();
		InetAddress ia = InetAddress.getLocalHost();
		data.put("action", "serverconnection");
		data.put("path", path);
		String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		data.put("manpubkey", encodedKey);
		byte[] b1 = data.toString().getBytes();
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 9000);
		ds.send(dp1);	

		char[] password = "".toCharArray();
		String alias = "1";
		PrivateKey privateKey1 = (PrivateKey) p12.getKey(alias, password);
		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) p12.getEntry(alias, new KeyStore.PasswordProtection(password));
		//System.out.println(encoder.encodeToString(privateKey1.getEncoded()));

		//Generate public and private keys
		
		
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

		while(true) {
			byte[] b = new byte[1024];
			DatagramPacket dp = new DatagramPacket(b, b.length);
			ds.receive(dp);
			String line = new String(dp.getData());
			JSONObject jsonObject = new JSONObject(line);
			readCommand(jsonObject, dp, ds);
		}
	}

	static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws KeyStoreException, CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		//Receive repository's public key
		if(jsonObject.get("action").equals("serverconnection")) {
			KeyStore p12 = KeyStore.getInstance("pkcs12");
			p12.load(new FileInputStream(jsonObject.getString("path")), "".toCharArray());
			Enumeration e = p12.aliases();
			Principal issuer = null;
			while (e.hasMoreElements()) {
				String alias = (String) e.nextElement();
				X509Certificate c = (X509Certificate) p12.getCertificate(alias);
				issuer = c.getIssuerDN();
			}
			if(issuerman.equals(issuer)) {
				repositoryPublicKey = getKey(jsonObject.getString("reppubkey"));
				System.out.println("Servers are connected successfuly");
			}
			else
				System.out.println("Repository not trustable!");
		}
		
		//Client connection
		if(jsonObject.get("action").equals("newclient")) {
			//Give client manager's public key
			JSONObject data = new JSONObject();
			InetAddress ia = InetAddress.getLocalHost();
			data.put("seq", jsonObject.getInt("seq") + 1);
			String manpubkey = encoder.encodeToString(publicKey.getEncoded());
			data.put("manpubkey", manpubkey);
			byte[] b1 = data.toString().getBytes();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);

			byte[] b2 = new byte[1024];
			DatagramPacket dp2 = new DatagramPacket(b2, b2.length);
			ds.receive(dp2);
			String response1 = new String(dp2.getData());
			JSONObject jsonObject2 = new JSONObject(response1);
			byte[] decipheredkey = decipherRSA(decoder.decode(jsonObject2.getString("key")), privateKey);
			SecretKey sessionkey = new SecretKeySpec(decipheredkey, 0, decipheredkey.length, "AES");
			byte[] name = decipherAES(decoder.decode(jsonObject2.getString("creatorid")), sessionkey);
			Client c = new Client(sessionkey, new String(name), jsonObject2.getString("creatorid"), counter);
			clients.add(c);
			counter++;
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

			//receive ack from rep and send ack to client
			byte[] b1 = new byte[1024];
			DatagramPacket dp2 = new DatagramPacket(b1, b1.length);
			ds.receive(dp2);
			String response = new String(dp2.getData());
			JSONObject jo = new JSONObject(response);
			if(jo.getInt("ack") == 1) {
				jo.put("seq", jsonObject.getInt("seq") + 1);
				byte[] b2 = jo.toString().getBytes();
				DatagramPacket dp3 = new DatagramPacket(b2, b2.length, ia, dp.getPort());
				ds.send(dp3);
			}
		}
		
		//New bid
		if(jsonObject.get("action").equals("bid")) {
			if(jsonObject.getString("type").equals("blind")) {
				//falta tratar quando é blind
			}
			else {
				//falta bid tem de ser maior que a última
				byte[] decipheredkey = decipherRSA(decoder.decode(jsonObject.getString("key2")), privateKey);
				SecretKey originalKey = new SecretKeySpec(decipheredkey, 0, decipheredkey.length, "AES");
				byte[] decipheredvalue = decipherAES(decoder.decode(jsonObject.getString("value")), originalKey);
				String s = new String(decipheredvalue);
				jsonObject.remove("value");
				System.out.println(jsonObject.getString("prevbid") + " - " + s);
				if(Integer.parseInt(jsonObject.getString("prevbid")) >= Integer.parseInt(s)) {
					jsonObject.put("value", "error");
				}
				else {
					jsonObject.put("value", s);
				}
			}

			byte[] b = jsonObject.toString().getBytes();
			InetAddress inet = InetAddress.getLocalHost();
			DatagramPacket d = new DatagramPacket(b, b.length, inet, 9000);
			ds.send(d);

			//Missing: signature for receipt

			/*BufferedWriter writer = new BufferedWriter(new FileWriter("Receipts/client" + jsonObject.getInt("creatorid") + ".txt", true));
			writer.append(jsonObject.toString() + "\n");
			writer.close();*/
		}

		if(jsonObject.get("action").equals("terminate")) {
			//falta isto
		}

		if(jsonObject.get("action").equals("checkcont")) {
			byte[] b = jsonObject.toString().getBytes();
			InetAddress inet = InetAddress.getLocalHost();
			DatagramPacket d = new DatagramPacket(b, b.length, inet, 9000);
			ds.send(d);

			byte[] res = new byte[1024];
			DatagramPacket resp = new DatagramPacket(res, res.length);
			ds.receive(resp);
			String r = new String(resp.getData());
			JSONObject jo = new JSONObject(r);
			
			String str = "";
			for(int c = 0; c < clients.size(); c++) {
				System.out.println(clients.get(c).s + " - " + jo.get("bidder"));
				if(clients.get(c).s.equals(jo.get("bidder"))) {
					str = "The winner is " + clients.get(c).name + " with a bid of " + jo.get("bid");
				}
			}
			JSONObject j = new JSONObject();
			j.put("seq", jo.getInt("seq"));
			j.put("winner", str);
			System.out.println(j.toString());
			byte[] by = j.toString().getBytes();
			DatagramPacket pack = new DatagramPacket(by, by.length, inet, dp.getPort());
			ds.send(pack);
		}

		else if(jsonObject.get("action").equals("bidsbyclient")) {
			String s = "\n";
			for(int i = 0; i < clients.size(); i++) {
				s += "Client: " + clients.get(i).id + " | Name: " + clients.get(i).name + "\n";
			}
			JSONObject obj = new JSONObject();
			obj.put("options", s);
			obj.put("seq", jsonObject.getInt("seq") + 1);
			byte[] b1 = obj.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}

		else if(jsonObject.get("action").equals("clientcont")) {
			JSONObject obj = new JSONObject();
			for(int i = 0; i < clients.size(); i++) {
				if(clients.get(i).id == jsonObject.getInt("client")) {
					obj.put("name", clients.get(i).s);
				}
			}
			obj.put("seq", jsonObject.getInt("seq") + 1);
			obj.put("action", "clientcont");
			byte[] b1 = obj.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 9000);
			ds.send(dp1);

			byte[] res = new byte[1024];
			DatagramPacket resp = new DatagramPacket(res, res.length);
			ds.receive(resp);
			String r = new String(resp.getData());
			byte[] x = r.getBytes();
			DatagramPacket d = new DatagramPacket(x, x.length, ia, dp.getPort());
			ds.send(d);
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

	static byte[] decipherAES(byte[] in, SecretKey key) {
		try {
			Cipher aesCipher = Cipher.getInstance("AES");
			aesCipher.init(Cipher.DECRYPT_MODE, key);
			return aesCipher.doFinal(in);
		}
		catch(Exception e) {
	        e.printStackTrace();
		}
		return null;
	}
}
