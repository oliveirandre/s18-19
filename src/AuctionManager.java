import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.Map;
import java.util.HashMap;
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
import java.util.List;

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
	private static String path = "certs/man.crt";
	private static Principal issuerman = null;
	static List<Client> clients = new ArrayList<Client>();
	private static PublicKey publicKey = null;
	private static PrivateKey privateKey = null;
	private static SecretKey secKey = null;
	private static Principal p = null;
	private static KeyPair kp = null;
	private static PublicKey repositoryPublicKey = null;
	private static HashMap<String, String> bids = new HashMap<String, String>();
	private static HashMap<Integer, HashMap<String, String>> blind = new HashMap<Integer, HashMap<String, String>>();
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws SignatureException, KeyStoreException, UnrecoverableKeyException, UnrecoverableEntryException, CertificateException, IOException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		
		generateKeys();

		FileInputStream fin = new FileInputStream("certs/man.crt");
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) f.generateCertificate(fin);
		publicKey = cert.getPublicKey();
		p = cert.getIssuerDN();

		//read own certificate
		KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream("certs/man.p12"), "".toCharArray());
		privateKey = (PrivateKey) p12.getKey("1", "".toCharArray());

		//Send certificate path to repository
		DatagramSocket ds = new DatagramSocket(8000);
		JSONObject data = new JSONObject();
		InetAddress ia = InetAddress.getLocalHost();
		data.put("action", "serverconnection");
		data.put("path", path);
		byte[] b1 = data.toString().getBytes();
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 9000);
		ds.send(dp1);	

		while(true) {
			byte[] b = new byte[2048];
			DatagramPacket dp = new DatagramPacket(b, b.length);
			ds.receive(dp);
			String line = new String(dp.getData());
			JSONObject jsonObject = new JSONObject(line);
			readCommand(jsonObject, dp, ds);
		}
	}

	static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws SignatureException, KeyStoreException, CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		//Receive repository's public key
		if(jsonObject.get("action").equals("serverconnection")) {

			FileInputStream f = new FileInputStream(jsonObject.getString("path"));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate c = (X509Certificate) cf.generateCertificate(f);
			Principal issuer = c.getIssuerDN();

			if(issuer.equals(p)) {
				repositoryPublicKey = c.getPublicKey();
				System.out.println("Servers are connected!");
			}
			else { 
				System.out.println("Repository not trustable!");
				System.exit(0);
			}
		}
		
		//Client connection
		if(jsonObject.get("action").equals("newclient")) {
			//Give client manager's public key
			JSONObject data = new JSONObject();
			InetAddress ia = InetAddress.getLocalHost();
			data.put("seq", jsonObject.getInt("seq") + 1);
			data.put("path", path);
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
				System.out.println(jsonObject.toString());
				//falta tratar quando é blind
				byte[] decipheredkey = decipherRSA(decoder.decode(jsonObject.getString("key2")), privateKey);
				SecretKey originalKey = new SecretKeySpec(decipheredkey, 0, decipheredkey.length, "AES");
				byte[] decipheredvalue = decipherAES(decoder.decode(jsonObject.getString("value")), originalKey);
				//byte[] decipheredbidder = decipherAES(decoder.decode(jsonObject.getString("bidder")), originalKey);
				byte[] cipheredvalue = cipherAES(decipheredvalue);
				//byte[] deciphered2 = decipherAES(decoder.decode(encoder.encode(cipheredvalue)), secKey);
				//System.out.println(new String(deciphered2));
				//byte[] cipheredbidder = cipherAES(decipheredbidder);
				//jsonObject.remove("bidder");
				jsonObject.remove("value");
				jsonObject.put("value", new String(encoder.encode(cipheredvalue)));
				//jsonObject.put("bidder", new String(cipheredbidder));
				//String val = new String(decipheredvalue);
				//String bidder = new String(decipheredbidder);
				//CONTINUAR AQUI, GUARDAR ID DA AUCTION, BIDDER E VALOR DA BID, para saber vencedor posteriormente
				//blind.put(jsonObject.getInt("auction"), bids);
			}
			else {
				//falta bid tem de ser maior que a última
				byte[] decipheredkey = decipherRSA(decoder.decode(jsonObject.getString("key2")), privateKey);
				SecretKey originalKey = new SecretKeySpec(decipheredkey, 0, decipheredkey.length, "AES");
				byte[] decipheredvalue = decipherAES(decoder.decode(jsonObject.getString("value")), originalKey);
				//byte[] decipheredbidder = decipherAES(decoder.decode(jsonObject.getString("bidder")), originalKey);
				String s = new String(decipheredvalue);
				validBid valid = new validBid(jsonObject, Integer.parseInt(s));
				if(!valid.validateValue()){
					jsonObject.put("error", 1);
				}else if(!valid.validateMaxBids()){
					jsonObject.put("error", 2);
				}
				else {
					jsonObject.remove("value");
					jsonObject.put("value", s);
					//byte[] cipheredbidder = cipherAES(decipheredbidder);
					//jsonObject.remove("bidder");
					//jsonObject.put("bidder", new String(cipheredbidder));
					jsonObject.put("error", 0);
				}
			}
			
			JSONObject jo = jsonObject;

			byte[] sign = jo.toString().getBytes();
			//sign the bid
			/*Signature dsa = Signature.getInstance("MD5withRSA");
			dsa.initSign(kp.getPrivate());
			dsa.update(sign);
			byte[] signatureBytes = dsa.sign();
			FileOutputStream sigfos = new FileOutputStream("Receipts/man-" + jo.get("creatorid") + jo.getInt("bidnumber") + ".txt");
			sigfos.write(signatureBytes);
			sigfos.close();*/

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

		if(jsonObject.get("action").equals("showbids")) {
			System.out.println(jsonObject.toString());
			List<String> l = new ArrayList<String>();
			if(jsonObject.get("type").equals("blind")) {
				for(int i = 0; i < jsonObject.getInt("nbids"); i++) {
					if(i == 0) {
						l.add("0");
						jsonObject.remove("bids" + i);
						jsonObject.remove("bidder" + i);
					}
					else {
						byte[] val = decipherAES(decoder.decode(jsonObject.getString("bids" + i)), secKey);
						for(int n = 0; n < clients.size(); n++) {
							if(jsonObject.getString("bidder" + i).equals(clients.get(n).s))
								l.add(new String(val) + " by " + clients.get(n).name);
						}
						jsonObject.remove("bids" + i);
						jsonObject.remove("bidder" + i);
					}
				}
			}
			else {
				for(int i = 0; i < jsonObject.getInt("nbids"); i++) {
					if(i == 0) {
						l.add("0");
						jsonObject.remove("bids" + i);
						jsonObject.remove("bidder" + i);
					}
					else {
						for(int n = 0; n < clients.size(); n++) {
							if(jsonObject.getString("bidder" + i).equals(clients.get(n).s))
								l.add(jsonObject.get("bids" + i) + " by " + clients.get(n).name);
						}
						jsonObject.remove("bids" + i);
						jsonObject.remove("bidder" + i);
					}
				}
			}
			jsonObject.put("bids", l.toString());
			System.out.println(jsonObject.toString());
			byte[] o = jsonObject.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(o, o.length, ia, 9000);
			ds.send(dp1);
		}

		if(jsonObject.get("action").equals("checkoutcome")) {
			//byte[] decipheredkey = decipherRSA(decoder.decode(jsonObject.getString("key")), privateKey);
			//SecretKey originalKey = new SecretKeySpec(decipheredkey, 0, decipheredkey.length, "AES");
			//byte[] decipheredclient = decipherAES(decoder.decode(jsonObject.getString("creatorid")), originalKey);
			//byte[] cipheredclient = cipherAES(decipheredclient);
			//jsonObject.remove("key");
			//jsonObject.remove("creatorid");
			//jsonObject.put("creatorid", new String(cipheredclient));
			//InetAddress ia = InetAddress.getLocalHost();
			//byte[] b = jsonObject.toString().getBytes();
			//DatagramPacket dp0 = new DatagramPacket(b, b.length, ia, 8000);
			//ds.send(dp0);
			/*
			byte[] b1 = new byte[1024];
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
			ds.receive(dp1);
			String response = new String(dp1.getData());
			JSONObject jo = new JSONObject(response);
			jo.put("seq", jsonObject.getInt("seq") + 1);
			byte[] b2 = jo.toString().getBytes();
			DatagramPacket dp2 = new DatagramPacket(b2, b2.length, ia, dp.getPort());
			ds.send(dp2);
			*/
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
			int winner = 0;
			int k = 0;
			String bidder = "";
			
			if(jo.get("type").equals("ascending")) {
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
			else {
				for(int i = 0; i < jo.getInt("options"); i++) {
					if(i == 0) {
						winner = 0;
					}
					else {
						System.out.println(jo.getString("value"+i));
						byte[] val = decipherAES(decoder.decode(jo.getString("value" + i)), secKey);
						if(Integer.parseInt(new String(val)) >= winner) {
							winner = Integer.parseInt(new String(val));
							k = i;
						}
					}
					//byte[] deciphered2 = decipherAES(decoder.decode(encoder.encode(cipheredvalue)), secKey);
					//byte[] decipheredclient = decipherAES(decoder.decode(jsonObject.getString("creatorid")), originalKey);					
				}
				for(int n = 0; n < clients.size(); n++) {
					if(jo.getString("bidder" + k).equals(clients.get(n).s))
						bidder = clients.get(n).name;
				}
				JSONObject j = new JSONObject();
				j.put("seq", jo.getInt("seq"));
				j.put("winner", "Winner is " + bidder + " with a bid of " + winner);
				System.out.println(j.toString());
				byte[] by = j.toString().getBytes();
				DatagramPacket pack = new DatagramPacket(by, by.length, inet, dp.getPort());
				ds.send(pack);
			}
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
			JSONObject jo = new JSONObject(r);

			String list = "";

			for(int i = 0; i < jo.getInt("sum"); i++) {
				if(jo.getInt("type2"+i) == 0) {
					list += "Open - Auction number " + jo.getInt("auction"+i) + " | Description: " + jo.get("description"+i) + " | Value of bid: " + jo.get("bid"+i) + "\n";
				}
				else {
					if(jo.get("type"+i).equals("blind")) {
						byte[] val = decipherAES(decoder.decode(jo.getString("bid" + i)), secKey);
						list += "Terminated - Auction number " + jo.getInt("auction"+i) + " | Description: " + jo.get("description"+i) + " | Value of bid: " + new String(val) + "\n";
					}
					else {
						list += "Terminated - Auction number " + jo.getInt("auction"+i) + " | Description: " + jo.get("description"+i) + " | Value of bid: " + jo.get("bid"+i) + "\n";
					}
				}
			}

			JSONObject j = new JSONObject();
			j.put("bids", list);
			j.put("seq", jo.getInt("seq"));
			byte[] x = j.toString().getBytes();
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
		/*KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		kp = kpg.generateKeyPair();
		publicKey = kp.getPublic();
		privateKey = kp.getPrivate();*/
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


class validBid implements validateBid{
	int bid;
	JSONObject j;
	public validBid(JSONObject j, int bid){
		this.j=j;
		this.bid=bid;
	}
	
	 public boolean validateValue(){
		if(Integer.parseInt(j.getString("prevbid")) > bid){
			return false;
		}
		return true;
	}
	public boolean validateMaxBids(){
		if(Integer.parseInt(j.getString("numBid")) == Integer.parseInt(j.getString("maxBids"))){
			return false;
		}
		return true;
	}
}