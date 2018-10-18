import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
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
	
	public Blockchain() throws NoSuchAlgorithmException {
		this.chain.add(createGenesis());
		this.difficulty = 4;
	}
	
	public Block createGenesis() throws NoSuchAlgorithmException {
		Date timestamp = new Date();
		return new Block(0, "Genesis Block", timestamp.toString(), "0");
	}
	
	public Block getLatestBlock() {
		return this.chain.get(this.chain.size() - 1);
	}
	
	public void addBlock(Block newBlock) throws NoSuchAlgorithmException {
		newBlock.previousHash = this.getLatestBlock().hash;
		newBlock.mineBlock(this.difficulty);
		//newBlock.hash = newBlock.calculateHash();
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
}

public class AuctionRepository {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		/*
		Blockchain test = new Blockchain();
		
		System.out.println("Genesis Block Hash: \n" + test.getLatestBlock().hash);
		
		System.out.println("\nMining block 1...");
		JSONObject block1 = new JSONObject();
		block1.put("amount", "40");
		test.addBlock(new Block(1, block1.toString(), ""));
		//System.out.println(test.getLatestBlock().hash);
		System.out.println("prev " + test.getLatestBlock().previousHash);

		System.out.println("\nMining block 2...");
		JSONObject block2 = new JSONObject();
		block1.put("amount", "1000");
		test.addBlock(new Block(2, block2.toString(), ""));
		//System.out.println(test.getLatestBlock().hash);
		System.out.println("prev " + test.getLatestBlock().previousHash);*/
	}
	
}
