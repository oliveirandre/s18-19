import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

class Block {
	
	int index;
	String data;
	String previousHash = "";
	String timestamp;
	String hash;
	int nonce;
	
	public Block(int index, String data, String timestamp, String previousHash) throws NoSuchAlgorithmException {
		this.index = index;
		this.data = data;
		this.timestamp = timestamp;
		this.previousHash = previousHash;
		this.hash = this.calculateHash();
		this.nonce = 0;
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
	
	public Blockchain(int id, String description, String creator) throws NoSuchAlgorithmException {
		this.chain.add(createGenesis());
		this.difficulty = 4;
		this.id = id;
		this.description = description;
		this.creator = creator;
	}
	
	public Block createGenesis() throws NoSuchAlgorithmException {
		Date timestamp = new Date();
		return new Block(i, "0", timestamp.toString(), "0");
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

	static int blockchainid = 0;
	static List<Blockchain> auctions = new ArrayList<Blockchain>();
	static List<Blockchain> terminated = new ArrayList<Blockchain>();
	private static Key pub;
	private static Key prv;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
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
	
	public static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws IOException, NoSuchAlgorithmException, JSONException {
		//KEY EXCHANGE BETWEEN SERVERS
		if(jsonObject.get("action").equals("serverconnection")) {
			System.out.println(jsonObject.getString("pubkey"));
			byte[] pubManagerBytes = decoder.decode(jsonObject.getString("pubkey"));
			Key pubManagerKey = new SecretKeySpec(pubManagerBytes, 0, pubManagerBytes.length, "DES"); ;
			JSONObject data = new JSONObject();
			data.put("action", "serverconnection");
			String repPubKey = encoder.encodeToString(pub.getEncoded());
			data.put("pubkey", repPubKey);
			byte[] b1 = data.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
			ds.send(dp1);	
		}
		
		//CREATE AN AUCTION ON THE REPOSITORY, AFTER PASSING THROUGH THE MANAGER
		if(jsonObject.get("action").equals("create")) { 
			Blockchain blockChain = new Blockchain(blockchainid, jsonObject.getString("description"), jsonObject.getString("creatorid"));
			blockchainid++;
			auctions.add(blockChain);
			System.out.println("Genesis Block Hash of Blockchain " + blockChain.id + ": \n" + blockChain.getLatestBlock().hash);
		}
		
		//LISTS ALL AUCTIONS AFTER A REQUEST FROM A CLIENT
		else if(jsonObject.get("action").equals("list")) {
			String list = "";
			for(int i = 0; i < auctions.size(); i++) {
				list += "Auction number: " + auctions.get(i).id + " | Description: " + auctions.get(i).description + " | Creator: " + auctions.get(i).creator + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + "\n";
			}
			byte[] b1 = list.getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//LISTS ALL AUCTIONS FROM OTHER CLIENTS
		else if(jsonObject.get("action").equals("listothers")) {
			String list = "";
			for(int i = 0; i < auctions.size(); i++) {
				if(!auctions.get(i).creator.equals(jsonObject.getString("creatorid"))) {
					list += "Auction number: " + auctions.get(i).id + " | Description: " + auctions.get(i).description + " | Creator: " + auctions.get(i).creator + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + "\n";	
				}
			}
			byte[] b1 = list.getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//LISTS ALL AUCTIONS FROM THIS CLIENT
		else if(jsonObject.get("action").equals("listmine")) {
			String list = "";
			for(int i = 0; i < auctions.size(); i++) {
				if(auctions.get(i).creator.equals(jsonObject.getString("creatorid"))) {
					list += "Auction number: " + auctions.get(i).id + " | Description: " + auctions.get(i).description + " | Creator: " + auctions.get(i).creator + " | Current highest bid: " + auctions.get(i).getLatestBlock().data + "\n";
				}
			}
			byte[] b1 = list.getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//BIDS ON AN EXISTING AUCTION AFTER A REQUEST FROM A CLIENT
		else if(jsonObject.get("action").equals("bid")) {
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
						auctions.get(i).addBlock(new Block(index, jsonObject.get("value").toString(), jsonObject.getString("timestamp"), ""));
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
		
		//TERMINATES AN AUCTION AFTER A REQUEST FROM A CLIENT
		else if(jsonObject.get("action").equals("terminate")) {
			for(int i = 0; i < auctions.size(); i++) {
				if(i == jsonObject.getInt("position")) {
					terminated.add(auctions.get(i));
					auctions.remove(i);
				}
			}
		}
		
		//SHOWS BIDS OF AN AUCTION
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
	static void generateKeys() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Key pub = kp.getPublic();
		Key pvt = kp.getPrivate();		
		//String outFile = "private";
		Base64.Encoder encoder = Base64.getEncoder();
		//Writer out = new FileWriter(outFile + ".key");
		//out.write(encoder.encodeToString(pvt.getEncoded()));
		//out.close();
	}
}
