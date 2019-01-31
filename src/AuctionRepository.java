import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.json.JSONException;
import org.json.JSONObject;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.io.*;
import com.sun.javafx.util.TempState;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.security.Principal;


class ClientR {

	SecretKey sessionkey;
	String name;

	public ClientR(SecretKey sessionkey, String name) {
		this.sessionkey = sessionkey;
		this.name = name;
	}

}

class Block {
	
	int index;
	String data;
	String previousHash = "";
	String timestamp;
	String hash;
	int nonce;
	String bidder;
	
	public Block(int index, String data, String timestamp, String previousHash, String bidder) throws NoSuchAlgorithmException {
		this.index = index;
		this.data = data;
		this.timestamp = timestamp;
		this.previousHash = previousHash;
		this.hash = this.calculateHash();
		this.nonce = 0;
		this.bidder = bidder;
	}
	
	public String calculateHash() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String input = this.index + this.previousHash + this.data.toString() + this.timestamp.toString() + this.nonce;
		md.update(input.getBytes());
		byte[] digest = md.digest();
		StringBuffer sb = new StringBuffer();
		for(byte b : digest) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}
	
	public void mineBlock(int difficulty) throws NoSuchAlgorithmException {
		String comparison = "";
		for(int i = 0; i < difficulty; i++) {
			comparison += "0";
		}		
		while(!this.hash.substring(0, difficulty).equals(comparison)) {		
			this.nonce++;			
			this.hash = this.calculateHash();
		}
		System.out.println("Block mined: " + this.hash);
	}
}

class Blockchain {
	
	List<Block> chain = new ArrayList<Block>();
	int difficulty;
	int id;
	String creator;
	String description;
	int i = 0;
	String type;
	String name;
	
	public Blockchain(int id, String description, String creator, String type, String name) throws NoSuchAlgorithmException {
		this.chain.add(createGenesis());
		this.difficulty = 0;
		this.id = id;
		this.description = description;
		this.creator = creator;
		this.type = type;
		this.name = name;
	}
	
	public Block createGenesis() throws NoSuchAlgorithmException {
		Date timestamp = new Date();
		return new Block(i, "0", timestamp.toString(), "0", "");
	}
	
	public Block getLatestBlock() {
		return this.chain.get(this.chain.size() - 1);
	}
	
	public void addBlock(Block newBlock) throws NoSuchAlgorithmException {
		i++;
		newBlock.index = i;
		newBlock.previousHash = this.getLatestBlock().hash;
		newBlock.mineBlock(this.difficulty);
		this.chain.add(newBlock);
	}
	
	public boolean isChainValid() throws NoSuchAlgorithmException {
		for(int i = 1; i < this.chain.size(); i++) {
			Block currentBlock = chain.get(i);
			Block previousBlock = chain.get(i-1);
			/*if(currentBlock.hash != currentBlock.calculateHash()) {
				System.out.println("oi1");
				return false;
			}*/
			if(currentBlock.previousHash != previousBlock.hash) {
				System.out.println("invalid bid");
				return false;
			}
		}
		System.out.println("New block added to blockchain number " + this.id);
		return true;
	}
	
	public List<String> printChain() {
		List<String> bids = new ArrayList<String>();
		for(int i = 0; i < chain.size(); i++) {
			bids.add(chain.get(i).data);
		}
		return bids;
	}
}

public class AuctionRepository {

	static List<ClientR> clients = new ArrayList<ClientR>();
	static int blockchainid = 0;
	static List<Blockchain> auctions = new ArrayList<Blockchain>();
	static List<Blockchain> terminated = new ArrayList<Blockchain>();
	static Principal issuerrep = null;
	static String path = "certs/rep.p12";
	private static Key managerPublicKey = null;
	private static SecretKey secKey = null;
	private static Key publicKey = null;
	private static Key privateKey = null;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws  KeyStoreException, CertificateException,IOException, NoSuchAlgorithmException, InvalidKeyException, JSONException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		
		//read own certificate
		KeyStore p12 = KeyStore.getInstance("pkcs12");
		p12.load(new FileInputStream(path), "".toCharArray());
		Enumeration e = p12.aliases();
		while (e.hasMoreElements()) {
			String alias = (String) e.nextElement();
			X509Certificate c = (X509Certificate) p12.getCertificate(alias);
			issuerrep = c.getIssuerDN();
		}

		//Generate public and private keys
		generateKeys();

		DatagramSocket ds = new DatagramSocket(9000);
		while(true) {
			byte[] b = new byte[1024];
			DatagramPacket dp = new DatagramPacket(b, b.length);
			ds.receive(dp);
			String line = new String(dp.getData());
			JSONObject jsonObject = new JSONObject(line);
			readCommand(jsonObject, dp, ds);
		}
	}
	
	public static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, JSONException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		//Connection between servers
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
			
			//verificar se foram certificados pelo mesmo CA
			if(issuerrep.equals(issuer)) {
				//Receive manager's public key
				managerPublicKey = getKey(jsonObject.getString("manpubkey"));
				//Send repository's public key to manager
				JSONObject data = new JSONObject();
				data.put("path", path);
				data.put("action", "serverconnection");
				String repPubKey = encoder.encodeToString(publicKey.getEncoded());
				data.put("reppubkey", repPubKey);
				byte[] b1 = data.toString().getBytes();
				InetAddress ia = InetAddress.getLocalHost();
				DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
				ds.send(dp1);	
			}
			else {
				System.out.println("Manager not trustable!");
			}			
		}
		
		//New client connection
		if(jsonObject.get("action").equals("newclient")) {
			JSONObject data = new JSONObject();
			InetAddress ia = InetAddress.getLocalHost();
			String reppubkey = encoder.encodeToString(publicKey.getEncoded());
			data.put("reppubkey", reppubkey);
			data.put("seq", jsonObject.getInt("seq") + 1);
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
			ClientR c = new ClientR(sessionkey, new String(name));
			clients.add(c);

			JSONObject jo = new JSONObject();
			jo.put("ack", 1);
			jo.put("seq", jsonObject2.getInt("seq") + 1);
			byte[] b = jo.toString().getBytes();
			DatagramPacket d = new DatagramPacket(b, b.length, ia, dp.getPort());
			ds.send(d);
		}
		
		//New auction
		if(jsonObject.get("action").equals("create")) { 
			//Data sent by the manager after auction being processed
			Blockchain blockChain = new Blockchain(blockchainid, jsonObject.getString("description"), jsonObject.getString("creatorid"), jsonObject.getString("type"), jsonObject.getString("name"));
			blockchainid++;
			auctions.add(blockChain);
			System.out.println("Genesis Block Hash of Blockchain " + blockChain.id + ": \n" + blockChain.getLatestBlock().hash);
			
			JSONObject data = new JSONObject();
			InetAddress ia = InetAddress.getLocalHost();
			data.put("ack", 1);
			byte[] b1 = data.toString().getBytes();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
			ds.send(dp1);
		}
		
		//List all auctions
		else if(jsonObject.get("action").equals("list")) {
			JSONObject data = new JSONObject();
			data.put("seq", jsonObject.getInt("seq") + 1);
			String list = "\n";
			for(int i = 0; i < auctions.size(); i++) {
				if(auctions.get(i).type.equals("blind")) {
					list += "Open - Auction number: " + auctions.get(i).id + " | Name: " + auctions.get(i).name + " | Description: " + auctions.get(i).description + " | Type: Blind Auction\n";
				}
				else {
					list += "Open - Auction number: " + auctions.get(i).id + " | Name: " + auctions.get(i).name + " | Description: " + auctions.get(i).description + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + "\n";
				}
			}
			for(int n = 0; n < terminated.size(); n++) {
				list += "Terminated - Auction number: " + terminated.get(n).id + " | Name: " + terminated.get(n).name + " | Description: " + terminated.get(n).description + "\n";
			}
			data.put("list", list);
			byte[] b1 = data.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//List all auctions from other clients
		else if(jsonObject.get("action").equals("listothers")) {
			String list = "";
			JSONObject data = new JSONObject();
			for(int i = 0; i < auctions.size(); i++) {
				if(auctions.get(i).type.equals("blind")) {
					if(!auctions.get(i).creator.equals(jsonObject.getString("creatorid")))
						list += "Auction number: " + auctions.get(i).id + " | Name: " + auctions.get(i).name + " | Description: " + auctions.get(i).description + " | Type: Blind Auction\n";
				
				}
				else {
					if(!auctions.get(i).creator.equals(jsonObject.getString("creatorid"))) {
						list += "Auction number: " + auctions.get(i).id + " | Name: " + auctions.get(i).name + " | Description: " + auctions.get(i).description + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + "\n";
					}
				}
			}
			data.put("seq", jsonObject.getInt("seq") + 1);
			data.put("list", list);
			byte[] b1 = data.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//List all auctions from this client
		else if(jsonObject.get("action").equals("listmine")) {
			String list = "";
			JSONObject data = new JSONObject();
			for(int i = 0; i < auctions.size(); i++) {
				if(auctions.get(i).type.equals("blind")) {
					list += "Auction number: " + auctions.get(i).id + " | Name: " + auctions.get(i).name + " | Description: " + auctions.get(i).description + " | Type: Blind Auction\n";
				}
				else {
					if(auctions.get(i).creator.equals(jsonObject.getString("creatorid"))) {
						list += "Auction number: " + auctions.get(i).id + " | Name: " + auctions.get(i).name + " | Description: " + auctions.get(i).description + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + "\n";
					}
				}
			}
			data.put("seq", jsonObject.getInt("seq") + 1);
			data.put("list", list);
			byte[] b1 = data.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//BIDS ON AN EXISTING AUCTION AFTER A REQUEST FROM A CLIENT
		else if(jsonObject.get("action").equals("bid")) {
			//Criptopuzzle
			int difficulty = 4;
			JSONObject crypto = new JSONObject();
			crypto.put("action", "bid");
			crypto.put("seq", jsonObject.getInt("seq") + 1);
			crypto.put("difficulty", difficulty);
			byte[] criptop = crypto.toString().getBytes();
			InetAddress ia1 = InetAddress.getLocalHost();
			DatagramPacket dp3 = new DatagramPacket(criptop, criptop.length, ia1, dp.getPort());
			ds.send(dp3);

			//Criptopuzzle received 
			byte[] resp = new byte[1024];
			DatagramPacket respp = new DatagramPacket(resp, resp.length);
			ds.receive(respp);
			String r = new String(respp.getData());
			JSONObject jo = new JSONObject(r);
			byte[] decipheredkey = decipherRSA(decoder.decode(jo.getString("key")), privateKey);
			//System.out.println(encoder.encodeToString(decipheredkey));
			SecretKey originalKey = new SecretKeySpec(decipheredkey, 0, decipheredkey.length, "AES");
			//System.out.println(encoder.encodeToString(originalKey.getEncoded()));
			byte[] decipheredHash = decipherAES(decoder.decode(jo.getString("hash")), originalKey);
			String s = new String(decipheredHash);

			//faltam coisas 
			boolean ver = false;
			int auction = jo.getInt("auction");
			for(int i = 0; i < auctions.size(); i++) {
				//|| !jo.get("creatorid").equals(auctions.get(i).creator)
				if(i == auction ) {
					jo.put("type", auctions.get(i).type);
					if(auctions.get(i).type.equals("ascending")) {
						jo.put("prevbid", auctions.get(i).getLatestBlock().data);
					}
					else 
						jo.put("prevbid", "unavailable");
				}
				else
					ver = true;
			}

			//Cryptopuzzle verification!
			if(!s.substring(0, difficulty).equals("0000") || ver == true) {
				JSONObject obj = new JSONObject();
				obj.put("ack", 0);
				obj.put("seq", jo.getInt("seq") + 1);
				byte[] o = obj.toString().getBytes();
				InetAddress inet = InetAddress.getLocalHost();
				DatagramPacket d = new DatagramPacket(o, o.length, inet, dp.getPort());
				ds.send(d);
			}

			//to rep
			byte[] man = jo.toString().getBytes();
			InetAddress inet2 = InetAddress.getLocalHost();
			DatagramPacket d2 = new DatagramPacket(man, man.length, inet2, 8000);
			ds.send(d2);

			//receber
			byte[] rman = new byte[1024];
			DatagramPacket resprman = new DatagramPacket(rman, rman.length);
			ds.receive(resprman);
			String r2 = new String(resprman.getData());
			JSONObject jobj = new JSONObject(r2);
			
			if(jobj.get("value").equals("error")) {
				JSONObject obj = new JSONObject();
				obj.put("ack", 2);
				obj.put("seq", jo.getInt("seq") + 1);
				byte[] o = obj.toString().getBytes();
				InetAddress inet = InetAddress.getLocalHost();
				DatagramPacket d = new DatagramPacket(o, o.length, inet, dp.getPort());
				ds.send(d);
			}
			else {
			int index = 0;
				for(int i = 0; i < auctions.size(); i++) {
					if(i == auction) {
						index = auctions.get(i).getLatestBlock().index;
						index++;
						auctions.get(i).addBlock(new Block(index, jobj.get("value").toString(), jobj.getString("timestamp"), "", jobj.getString("creatorid")));
						System.out.println(auctions.get(i).getLatestBlock().previousHash);
						auctions.get(i).isChainValid();
					}
				}

				//resposta
				JSONObject obj = new JSONObject();
				obj.put("ack", "1");
				obj.put("seq", jo.getInt("seq") + 1);
				byte[] o = obj.toString().getBytes();
				InetAddress inet = InetAddress.getLocalHost();
				DatagramPacket d = new DatagramPacket(o, o.length, inet, dp.getPort());
				ds.send(d);
			}
		}

		//Terminate an auction
		else if(jsonObject.get("action").equals("terminate")) {
			JSONObject data = new JSONObject();
			for(int i = 0; i < auctions.size(); i++) {
				if(i == jsonObject.getInt("position")) {
					if(auctions.get(i).creator.equals(jsonObject.get("creatorid"))) {
						terminated.add(auctions.get(i));
						auctions.remove(i);
						data.put("ack", 1);
					}
				}
				else
					data.put("ack", 0);
			}
			data.put("seq", jsonObject.getInt("seq") + 1);
			byte[] o = data.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(o, o.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//Show bids of an auction
		else if(jsonObject.get("action").equals("showbids")) {
			List<String> bids = new ArrayList<String>();
			int auction = jsonObject.getInt("auction");
			JSONObject obj = new JSONObject();
			for(int i = 0; i < auctions.size(); i++) {
				if(auctions.get(i).type.equals("blind")) {
					obj.put("bids", "none");
				}
				else {
					if(i == auction) {
						bids = auctions.get(i).printChain();
						obj.put("bids", bids.toString());
					}
				}
			}
			obj.put("seq", jsonObject.getInt("seq") + 1);
			byte[] o = obj.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(o, o.length, ia, dp.getPort());
			ds.send(dp1);
		}

		else if(jsonObject.get("action").equals("checkoutcome")) {
			String list = "\n";
			for(int i = 0; i < terminated.size(); i++) {
				for(int j = 0; j < terminated.get(i).chain.size(); j++) {
					if(terminated.get(i).chain.get(j).bidder.equals(jsonObject.get("creatorid"))) {
						list += "Auction number: " + terminated.get(i).id + " | Description: " + terminated.get(i).description + "\n";
					}
				}
			}
			JSONObject obj = new JSONObject();
			obj.put("options", list);
			obj.put("seq", jsonObject.getInt("seq") + 1);
			byte[] b1 = obj.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}

		else if(jsonObject.get("action").equals("checkcont")) {
			JSONObject obj = new JSONObject();
			for(int i = 0; i < terminated.size(); i++) {
				if(terminated.get(i).id == jsonObject.getInt("auction")) {
					obj.put("bidder", terminated.get(i).getLatestBlock().bidder);
					obj.put("bid", terminated.get(i).getLatestBlock().data);
					obj.put("type", terminated.get(i).type);
				}
			}
			obj.put("seq", jsonObject.getInt("seq") + 1);
			byte[] b1 = obj.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
			ds.send(dp1);
		}

		else if(jsonObject.get("action").equals("clientcont")) {
			String s = "\n";
			for(int j = 0; j < auctions.size(); j++) {
				if(!auctions.get(j).type.equals("blind")) {
					for(int k = 0; k < auctions.get(j).chain.size(); k++) {
						if(auctions.get(j).chain.get(k).bidder.equals(jsonObject.get("name"))) {
							s += "Open - Auction number: " + auctions.get(j).id + " | Description: " + auctions.get(j).description + " | Value of bid: " + auctions.get(j).chain.get(k).data + "\n";
							break;
						}
					}
				}
			}
			for(int j = 0; j < terminated.size(); j++) {
				for(int k = 0; k < terminated.get(j).chain.size(); k++) {
					if(terminated.get(j).chain.get(k).bidder.equals(jsonObject.get("name"))) {
						s += "Terminated - Auction number: " + terminated.get(j).id + " | Description: " + terminated.get(j).description + " | Value of bid: " + terminated.get(j).chain.get(k).data + "\n";
						break;
					}
				}
			}
			JSONObject obj = new JSONObject();
			obj.put("bids", s);
			obj.put("seq", jsonObject.getInt("seq"));
			byte[] b1 = obj.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
			ds.send(dp1);
		}
	}

	//Generate public and private keys
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
}
