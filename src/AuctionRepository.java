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
import java.security.PrivateKey;
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
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.security.Principal;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchProviderException;
import java.util.Random;
import java.security.cert.CertificateFactory;
import java.nio.charset.*;


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
	String minBid;
	String maxUserBids;

	public Blockchain(int id, String description, String creator, String type, String name, String minBid, String maxUserBids) throws NoSuchAlgorithmException {
		this.difficulty = 0;
		this.id = id;
		this.description = description;
		this.creator = creator;
		this.type = type;
		this.name = name;
		this.minBid = minBid;
		this.maxUserBids=maxUserBids;
		this.chain.add(createGenesis());
	}
	
	public Block createGenesis() throws NoSuchAlgorithmException {
		Date timestamp = new Date();
		return new Block(i, minBid, timestamp.toString(), "0", "");
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
	static String path = "certs/rep.crt";
	private static Key managerPublicKey = null;
	private static SecretKey secKey = null;
	private static Key publicKey = null;
	private static KeyPair kp = null;
	private static Key privateKey = null;
	private static Principal p = null;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws UnrecoverableKeyException, SignatureException, KeyStoreException, CertificateException,IOException, NoSuchAlgorithmException, InvalidKeyException, JSONException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {

		generateKeys();

		KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream("certs/rep.p12"), "".toCharArray());
		privateKey = (PrivateKey) p12.getKey("1", "".toCharArray());

		FileInputStream fin = new FileInputStream("certs/rep.crt");
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) f.generateCertificate(fin);
		publicKey = cert.getPublicKey();
		p = cert.getIssuerDN();

		DatagramSocket ds = new DatagramSocket(9000);
		while(true) {
			byte[] b = new byte[2048];
			DatagramPacket dp = new DatagramPacket(b, b.length);
			ds.receive(dp);
			String line = new String(dp.getData());
			JSONObject jsonObject = new JSONObject(line);
			readCommand(jsonObject, dp, ds);
		}
	}

	static String getAlphaNumericString(int n) 
    { 
  
        // chose a Character random from this String 
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    + "0123456789"
                                    + "abcdefghijklmnopqrstuvxyz"; 
  
        // create StringBuffer size of AlphaNumericString 
        StringBuilder sb = new StringBuilder(n); 
  
        for (int i = 0; i < n; i++) { 
  
            // generate a random number between 
            // 0 to AlphaNumericString variable length 
            int index 
                = (int)(AlphaNumericString.length() 
                        * Math.random()); 
  
            // add Character one by one in end of sb 
            sb.append(AlphaNumericString 
                          .charAt(index)); 
        } 
  
        return sb.toString(); 
    } 
	
	public static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws KeyStoreException, SignatureException, CertificateException, IOException, NoSuchAlgorithmException, JSONException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		//Connection between servers
		if(jsonObject.get("action").equals("serverconnection")) {

			String generatedString = getAlphaNumericString(10);

			FileInputStream f = new FileInputStream(jsonObject.getString("path"));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate c = (X509Certificate) cf.generateCertificate(f);
			Principal issuer = c.getIssuerDN();

			if(issuer.equals(p)) {
				System.out.println("Manager is trustable!");
				managerPublicKey = c.getPublicKey();
				JSONObject data = new JSONObject();
				byte[] toprove = cipherRSA(generatedString.getBytes(), managerPublicKey);
				data.put("path", path);
				data.put("prove", encoder.encodeToString(toprove));
				data.put("action", "serverconnection");
				byte[] b1 = data.toString().getBytes();
				InetAddress ia = InetAddress.getLocalHost();
				DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
				ds.send(dp1);	

				byte[] b2 = new byte[1024];
				DatagramPacket dp2 = new DatagramPacket(b2, b2.length);
				ds.receive(dp2);
				String response1 = new String(dp2.getData());
				JSONObject jsonObject2 = new JSONObject(response1);

				byte[] val = decipherRSA(decoder.decode(jsonObject2.getString("prove")), privateKey);

				if(new String(val).equals(generatedString)) {
					System.out.println("Servers are connected.");
				}
			}
			else { 
				System.out.println("Manager not trustable!");
				System.exit(0);
			}
		}
		
		//New client connection
		if(jsonObject.get("action").equals("newclient")) {
			JSONObject data = new JSONObject();
			InetAddress ia = InetAddress.getLocalHost();
			data.put("path", path);
			data.put("seq", jsonObject.getInt("seq") + 1);
			byte[] b1 = data.toString().getBytes();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);

			byte[] prove = new byte[1024];
			DatagramPacket dpr = new DatagramPacket(prove, prove.length);
			ds.receive(dpr);
			String resp = new String(dpr.getData());
			JSONObject jo2 = new JSONObject(resp);
			byte[] proven = decipherRSA(decoder.decode(jo2.getString("prove")), privateKey);
			jo2.remove("prove");
			jo2.put("prove", new String(proven));
			jo2.put("seq", jo2.getInt("seq") + 1);
			byte[] prov = jo2.toString().getBytes();
			DatagramPacket pack = new DatagramPacket(prov, prov.length, ia, dp.getPort());
			ds.send(pack);

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
			System.out.print(jsonObject.getString("minBid"));
			Blockchain blockChain = new Blockchain(blockchainid, jsonObject.getString("description"), jsonObject.getString("creatorid"), jsonObject.getString("type"), jsonObject.getString("name"), jsonObject.getString("minBid"), jsonObject.getString("maxBids"));
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
			String list = "";
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
				if(auctions.get(i).type.equals("blind") && auctions.get(i).creator.equals(jsonObject.getString("creatorid"))) {
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
			byte[] resp = new byte[2048];
			DatagramPacket respp = new DatagramPacket(resp, resp.length);
			ds.receive(respp);
			String r = new String(respp.getData());
			JSONObject jo = new JSONObject(r);
			if(jo.getInt("error") == 1) 
				return;

			byte[] decipheredkey = decipherRSA(decoder.decode(jo.getString("key")), privateKey);
			//System.out.println(encoder.encodeToString(decipheredkey));
			SecretKey originalKey = new SecretKeySpec(decipheredkey, 0, decipheredkey.length, "AES");
			//System.out.println(encoder.encodeToString(originalKey.getEncoded()));
			byte[] decipheredHash = decipherAES(decoder.decode(jo.getString("hash")), originalKey);
			String s = new String(decipheredHash);
			jo.remove("key");
			jo.remove("hash");

			//faltam coisas 
			boolean ver = false;
			int auction = jo.getInt("auction");
			for(int i = 0; i < auctions.size(); i++) {
				/*if(jo.get("creatorid").equals(auctions.get(i).creator)) {
					ver = true;
					break;
				}*/
				System.out.println(i + " - " + auction);
				int numBid=0;
				if(auctions.get(i).id == auction && !jo.get("creatorid").equals(auctions.get(i).creator)) {
					for(int k = 0; k < auctions.get(i).chain.size(); k++) {
						if(auctions.get(i).chain.get(k).bidder.equals(jo.get("creatorid"))){
							numBid++;
						}
					}
					jo.put("type", auctions.get(i).type);
					jo.put("prevbid", auctions.get(i).getLatestBlock().data);
					jo.put("auction", auctions.get(i).id);
					jo.put("bidder", jo.get("creatorid"));
					jo.put("numBid", String.valueOf(numBid));
					jo.put("maxBids", auctions.get(i).maxUserBids);
					ver = false;
					break;
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
				return;
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
			
			if(jobj.getInt("error") == 1) {
				JSONObject obj = new JSONObject();
				obj.put("ack", 2);
				obj.put("seq", jo.getInt("seq") + 1);
				byte[] o = obj.toString().getBytes();
				InetAddress inet = InetAddress.getLocalHost();
				DatagramPacket d = new DatagramPacket(o, o.length, inet, dp.getPort());
				ds.send(d);
			}
			else if(jobj.getInt("error") == 2){
				JSONObject obj = new JSONObject();
				obj.put("ack", 3);
				obj.put("seq", jo.getInt("seq") + 1);
				byte[] o = obj.toString().getBytes();
				InetAddress inet = InetAddress.getLocalHost();
				DatagramPacket d = new DatagramPacket(o, o.length, inet, dp.getPort());
				ds.send(d);
			}
			else {
				int index = 0;
				for(int i = 0; i < auctions.size(); i++) {
					if(auctions.get(i).id == auction) {
						index = auctions.get(i).getLatestBlock().index;
						index++;
						auctions.get(i).addBlock(new Block(index, jobj.getString("value"), jobj.getString("timestamp"), "", jobj.getString("bidder")));
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

		else if(jsonObject.get("action").equals("sign")) {

			JSONObject jo = jsonObject;

			System.out.println("???");

			//sign the bid
			Signature dsa = Signature.getInstance("MD5withRSA");
			dsa.initSign((PrivateKey) privateKey);
			FileInputStream fis = new FileInputStream("Receipts/bids-" + jsonObject.get("creatorid") + ".txt");
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			while ((len = bufin.read(buffer)) >= 0) {
				dsa.update(buffer, 0, len);
			};
			bufin.close();
			byte[] signatureBytes = dsa.sign();
			FileOutputStream sigfos = new FileOutputStream("Receipts/rep-" + jsonObject.get("creatorid") + ".txt");
			sigfos.write(signatureBytes);
			sigfos.close();

			System.out.println("signed.");

			InetAddress ia = InetAddress.getLocalHost();
			byte[] b = jo.toString().getBytes();
			DatagramPacket d = new DatagramPacket(b, b.length, ia, 8000);
			ds.send(d);

			byte[] rman = new byte[1024];
			DatagramPacket resprman = new DatagramPacket(rman, rman.length);
			ds.receive(resprman);
			String r2 = new String(resprman.getData());

			byte[] cl = r2.getBytes();
			DatagramPacket r = new DatagramPacket(cl, cl.length, ia, dp.getPort());
			ds.send(r);
		}

		else if(jsonObject.get("action").equals("verify")) {
			Signature sig = Signature.getInstance("MD5withRSA");
			sig.initVerify((PublicKey) publicKey);
			FileInputStream fis = new FileInputStream("Receipts/bids-" + jsonObject.get("creatorid") + ".txt");
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			while ((len = bufin.read(buffer)) >= 0) {
				sig.update(buffer, 0, len);
			};
			bufin.close();
			FileInputStream sigfis = new FileInputStream("Receipts/rep-" + jsonObject.get("creatorid") + ".txt");
			byte[] sigToVerify = new byte[sigfis.available()]; 
			sigfis.read(sigToVerify);
			sigfis.close();
			boolean verifies = sig.verify(sigToVerify);
			if(verifies == true) 
				jsonObject.put("verification", "true");
			else 
				jsonObject.put("verification", "false");
			int i = jsonObject.getInt("seq") + 1;
			jsonObject.remove("seq");
			jsonObject.put("seq", i + 1);
			byte[] b = jsonObject.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket d = new DatagramPacket(b, b.length, ia, dp.getPort());
			ds.send(d);
		}

		//Terminate an auction
		else if(jsonObject.get("action").equals("terminate")) {
			JSONObject data = new JSONObject();
			boolean ver = false;
			for(int i = 0; i < auctions.size(); i++) {
				System.out.println(i + " - " + jsonObject.getInt("position"));
				if(auctions.get(i).id == jsonObject.getInt("position")) {
					if(auctions.get(i).creator.equals(jsonObject.get("creatorid"))) {
						terminated.add(auctions.get(i));
						auctions.remove(i);
						data.put("ack", 1);
						ver = false;
						break;
					}
				}
				else
					ver = true;
			}
			if(ver == true)
				data.put("ack", 0);
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
			int nbids = 0;
			for(int i = 0; i < auctions.size(); i++) {
				if(auctions.get(i).type.equals("blind")) {
					obj.put("bids", "none");
				}
				else {
					if(auctions.get(i).id == auction) {
						bids = auctions.get(i).printChain();
						obj.put("bids", bids.toString());
					}
				}
			}
			int l = 0;
			for(int j = 0; j < terminated.size(); j++) {
				if(terminated.get(j).id == auction) {
					l = 1;
					for(int k = 0; k < terminated.get(j).chain.size(); k++) {
						obj.put("bids" + k, terminated.get(j).chain.get(k).data);
						obj.put("bidder" + k, terminated.get(j).chain.get(k).bidder);
						nbids++;
					}
					obj.put("type", terminated.get(j).type);
					obj.put("action", "showbids");
					obj.put("nbids", nbids);
					obj.put("seq", jsonObject.getInt("seq") + 1);
					System.out.println(obj.toString());
					byte[] o = obj.toString().getBytes();
					InetAddress ia = InetAddress.getLocalHost();
					DatagramPacket dp1 = new DatagramPacket(o, o.length, ia, 8000);
					ds.send(dp1);

					byte[] rman = new byte[1024];
					DatagramPacket resprman = new DatagramPacket(rman, rman.length);
					ds.receive(resprman);
					String r2 = new String(resprman.getData());
					byte[] o2 = r2.getBytes();
					DatagramPacket dp2 = new DatagramPacket(o2, o2.length, ia, dp.getPort());
					ds.send(dp2);
				}
			}
			if(l == 0) {
				System.out.println("?");
				obj.put("seq", jsonObject.getInt("seq") + 1);
				byte[] o = obj.toString().getBytes();
				InetAddress ia = InetAddress.getLocalHost();
				DatagramPacket dp1 = new DatagramPacket(o, o.length, ia, dp.getPort());
				ds.send(dp1);
			}
			
		}

		else if(jsonObject.get("action").equals("checkoutcome")) {
			String list = "";
			for(int i = 0; i < terminated.size(); i++) {
				for(int j = 0; j < terminated.get(i).chain.size(); j++) {
					System.out.println(terminated.get(i).chain.get(j).bidder + " - " + jsonObject.get("creatorid"));
					if(terminated.get(i).chain.get(j).bidder.equals(jsonObject.get("creatorid"))) {
						list += "Auction number: " + terminated.get(i).id + " | Description: " + terminated.get(i).description + "\n";
						break;
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
			int options = 0;
			for(int i = 0; i < terminated.size(); i++) {
				if(terminated.get(i).id == jsonObject.getInt("auction") && !terminated.get(i).type.equals("blind")) {
					obj.put("bidder", terminated.get(i).getLatestBlock().bidder);
					obj.put("bid", terminated.get(i).getLatestBlock().data);
					obj.put("type", terminated.get(i).type);
					break;
				}
				else {
					obj.put("type", terminated.get(i).type);
					for(int j = 0; j < terminated.get(i).chain.size(); j++) {
						obj.put("bidder" + j, terminated.get(i).chain.get(j).bidder);
						obj.put("value" + j, terminated.get(i).chain.get(j).data);
						options++;
					}
					obj.put("options", options);
				}
			}
			obj.put("seq", jsonObject.getInt("seq") + 1);
			System.out.println(obj.toString());
			byte[] b1 = obj.toString().getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 8000);
			ds.send(dp1);
		}

		else if(jsonObject.get("action").equals("clientcont")) {
			String s = "";
			int sum = 0;
			JSONObject obj = new JSONObject();
			for(int j = 0; j < auctions.size(); j++) {
				if(!auctions.get(j).type.equals("blind")) {
					for(int k = 0; k < auctions.get(j).chain.size(); k++) {
						if(auctions.get(j).chain.get(k).bidder.equals(jsonObject.get("name"))) {
							obj.put("type2"+sum, "0");
							obj.put("bid"+sum, auctions.get(j).chain.get(k).data);
							obj.put("auction"+sum, auctions.get(j).id);
							obj.put("description"+sum, auctions.get(j).description);
							sum++;
						}
					}
				}
			}
			for(int j = 0; j < terminated.size(); j++) {
				for(int k = 0; k < terminated.get(j).chain.size(); k++) {
					if(terminated.get(j).chain.get(k).bidder.equals(jsonObject.get("name"))) {
						obj.put("type2"+sum, "1");
						obj.put("type"+sum, terminated.get(j).type);
						obj.put("bid"+sum, terminated.get(j).chain.get(k).data);
						obj.put("auction"+sum, terminated.get(j).id);
						obj.put("description"+sum, terminated.get(j).description);
						sum++;
						//s += "Terminated - Auction number: " + terminated.get(j).id + " | Description: " + terminated.get(j).description + " | Value of bid: " + terminated.get(j).chain.get(k).data + "\n";
					}
				}
			}
			obj.put("sum", sum);
			obj.put("seq", jsonObject.getInt("seq"));
			System.out.println(obj.toString());
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
