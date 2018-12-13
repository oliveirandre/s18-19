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

class ClientR {

	String name;
	int id;
	PublicKey pub;

	public ClientR(String name, int id, PublicKey pub) {
		this.name = name;
		this.id = id;
		this.pub = pub;
	}

}

class Block {
	
	int index;
	String data;
	String previousHash = "";
	String timestamp;
	String hash;
	int nonce;
	int bidder;
	
	public Block(int index, String data, String timestamp, String previousHash, int bidder) throws NoSuchAlgorithmException {
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
	int creator;
	String description;
	int i = 0;
	
	public Blockchain(int id, String description, int creator) throws NoSuchAlgorithmException {
		this.chain.add(createGenesis());
		this.difficulty = 4;
		this.id = id;
		this.description = description;
		this.creator = creator;
	}
	
	public Block createGenesis() throws NoSuchAlgorithmException {
		Date timestamp = new Date();
		return new Block(i, "0", timestamp.toString(), "0", creator);
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
		for(int i = 0; i < this.chain.size(); i++) {
			Block currentBlock = chain.get(i);
			Block previousBlock = chain.get(i-1);
			if(currentBlock.hash != currentBlock.calculateHash())
				return false;
			if(currentBlock.previousHash != previousBlock.hash)
				return false;
		}
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

	private static int counter = 0;
	static List<ClientR> clients = new ArrayList<ClientR>();
	static int blockchainid = 0;
	static List<Blockchain> auctions = new ArrayList<Blockchain>();
	static List<Blockchain> terminated = new ArrayList<Blockchain>();
	private static Key managerPublicKey = null;
	private static SecretKey secKey = null;
	private static Key publicKey = null;
	private static Key privateKey = null;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, JSONException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
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
	
	public static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws IOException, NoSuchAlgorithmException, JSONException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		//Connection between servers
		if(jsonObject.get("action").equals("serverconnection")) {
			//Receive manager's public key
			managerPublicKey = getKey(jsonObject.getString("manpubkey"));

			//Send repository's public key to manager
			JSONObject data = new JSONObject();
			data.put("action", "serverconnection");
			String repPubKey = encoder.encodeToString(publicKey.getEncoded());
			data.put("reppubkey", repPubKey);
			byte[] b1 = data.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
			ds.send(dp1);	
		}
		
		//New client connection
		if(jsonObject.get("action").equals("newclient")) {
			counter++;
			PublicKey clientKey = getKey(jsonObject.getString("clientkey"));
			ClientR c = new ClientR(jsonObject.getString("name"), counter, clientKey);
			clients.add(c);

			System.out.println(jsonObject.getString("name") + " connected successfuly");

			//Send repository's public key to client
			JSONObject data = new JSONObject();
			InetAddress ia = InetAddress.getLocalHost();
			String reppubkey = encoder.encodeToString(publicKey.getEncoded());
			data.put("reppubkey", reppubkey);
			byte[] b1 = data.toString().getBytes();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//New auction
		if(jsonObject.get("action").equals("create")) { 
			//Data sent by the manager after auction being processed
			Blockchain blockChain = new Blockchain(blockchainid, jsonObject.getString("description"), jsonObject.getInt("creatorid"));
			blockchainid++;
			auctions.add(blockChain);
			System.out.println("Genesis Block Hash of Blockchain " + blockChain.id + ": \n" + blockChain.getLatestBlock().hash);
		}
		
		//List all auctions
		else if(jsonObject.get("action").equals("list")) {
			String list = "";
			String s = "";
			String bidder = "";
			for(int i = 0; i < auctions.size(); i++) {
				bidder = "";
				for(int j = 0; j < clients.size(); j++) {
					if(auctions.get(i).creator == clients.get(j).id)
						s = clients.get(j).name;
				}
				for(int k = 0; k < clients.size(); k++) {
					if(auctions.get(i).getLatestBlock().bidder == clients.get(k).id) {
						bidder = " by ";
						bidder += clients.get(k).name;
					}
				}
				list += "Auction number: " + auctions.get(i).id + " | Description: " + auctions.get(i).description + " | Creator: " + s + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + bidder + "\n";
			}
			byte[] b1 = list.getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//List all auctions from other clients
		else if(jsonObject.get("action").equals("listothers")) {
			String list = "";
			String s = "";
			String bidder = "";
			for(int i = 0; i < auctions.size(); i++) {
				bidder = "";
				for(int j = 0; j < clients.size(); j++) {
					if(auctions.get(i).creator == clients.get(j).id)
						s = clients.get(j).name;
				}
				for(int k = 0; k < clients.size(); k++) {
					if(auctions.get(i).getLatestBlock().bidder == clients.get(k).id) {
						bidder = " by ";
						bidder += clients.get(k).name;
					}
				}
				if(auctions.get(i).creator != jsonObject.getInt("creatorid")) {
					list += "Auction number: " + auctions.get(i).id + " | Description: " + auctions.get(i).description + " | Creator: " + s + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + bidder + "\n";
				}
			}
			byte[] b1 = list.getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//List all auctions from this client
		else if(jsonObject.get("action").equals("listmine")) {
			String list = "";
			String s = "";
			String bidder = "";
			for(int i = 0; i < auctions.size(); i++) {
				bidder = "";
				for(int j = 0; j < clients.size(); j++) {
					if(auctions.get(i).creator == clients.get(j).id)
						s = clients.get(j).name;
				}
				for(int k = 0; k < clients.size(); k++) {
					if(auctions.get(i).getLatestBlock().bidder == clients.get(k).id) {
						bidder = " by ";
						bidder += clients.get(k).name;
					}
				}
				if(auctions.get(i).creator == jsonObject.getInt("creatorid")) {
					list += "Auction number: " + auctions.get(i).id + " | Description: " + auctions.get(i).description + " | Creator: " + s + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + bidder + "\n";
				}
			}
			byte[] b1 = list.getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//BIDS ON AN EXISTING AUCTION AFTER A REQUEST FROM A CLIENT
		else if(jsonObject.get("action").equals("bid")) {
			//Criptopuzzle
			JSONObject crypto = new JSONObject();
			crypto.put("action", "bid");
			crypto.put("difficulty", 4);
			String bidder = "";
			String key = "";
			for(int i = 0; i < clients.size(); i++) {
				if(jsonObject.getInt("bidder") == clients.get(i).id) {
					bidder = clients.get(i).name;
					key = encoder.encodeToString(clients.get(i).pub.getEncoded());
				}
			}
			crypto.put("arg1", bidder);
			crypto.put("arg2", key);
			byte[] criptop = crypto.toString().getBytes();
			InetAddress ia1 = InetAddress.getLocalHost();
			DatagramPacket dp3 = new DatagramPacket(criptop, criptop.length, ia1, dp.getPort());
			ds.send(dp3);

			//Criptopuzzle received
			byte[] resp = new byte[1024];
			DatagramPacket respp = new DatagramPacket(resp, resp.length);
			ds.receive(respp);
			/*String r = new String(respp.getData());
			JSONObject jo = new JSONObject(r);
			byte[] decipheredkey = decipherRSA(jo.getString("key").getBytes(), privateKey);
			SecretKey originalKey = new SecretKeySpec(decipheredkey , 0, decipheredkey.length, "AES");
			byte[] decipheredHash = decipherAES(jo.getString("hash").getBytes(), originalKey);
			//faltam coisas */

			//resposta
			JSONObject obj = new JSONObject();
			obj.put("action", "bid");
			byte[] o = obj.toString().getBytes();
			InetAddress inet = InetAddress.getLocalHost();
			DatagramPacket d = new DatagramPacket(o, o.length, inet, dp.getPort());
			ds.send(d);
		}

		//Continuação do processamento da bid
		else if(jsonObject.get("action").equals("bidcont")) {
			int auction = jsonObject.getInt("auction");
			int index = 0;
			for(int i = 0; i < auctions.size(); i++) {
				if(i == auction) {
					if(Integer.parseInt(auctions.get(i).getLatestBlock().data) >= jsonObject.getInt("value")) {
						byte[] b1 = "Value inserted is inferior to the highest bid!".getBytes();
						InetAddress ia = InetAddress.getLocalHost();
						DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
						ds.send(dp1);
					}
					else {
						index = auctions.get(i).getLatestBlock().index;
						index++;
						auctions.get(i).addBlock(new Block(index, jsonObject.get("value").toString(), jsonObject.getString("timestamp"), "", jsonObject.getInt("creatorid")));
						byte[] b1 = jsonObject.toString().getBytes();
						InetAddress ia = InetAddress.getLocalHost();
						DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
						ds.send(dp1);
						byte[] b2 = "".getBytes();
						InetAddress ia2 = InetAddress.getLocalHost();
						DatagramPacket dp2 = new DatagramPacket(b2, b2.length, ia2, dp.getPort());
						ds.send(dp2);
					}
				}
			}
		}
		
		//Terminate an auction
		else if(jsonObject.get("action").equals("terminate")) {
			for(int i = 0; i < auctions.size(); i++) {
				if(i == jsonObject.getInt("position")) {
					terminated.add(auctions.get(i));
					auctions.remove(i);
				}
			}
		}
		
		//Show bids of an auction
		else if(jsonObject.get("action").equals("showbids")) {
			List<String> bids = new ArrayList<String>();
			int auction = jsonObject.getInt("auction");
			for(int i = 0; i < auctions.size(); i++) {
				if(i == auction) {
					bids = auctions.get(i).printChain();
				}
			}
			byte[] b1 = bids.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
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
			aesCipher.init(Cipher.ENCRYPT_MODE, key);
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
