import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import com.sun.javafx.css.CalculatedValue;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;

/*
 * -> As auctions têm de ser guardadas no AuctionRepository, e não no AuctionManager.
 * O cliente comunica com ambos ou só com o manager? Isto implica saber se o repositório
 * é preenchido pelo cliente ou pelo manager, deixando o manager como um "man in the middle"
 * em quase todos os pedidos do cliente, ou se o cliente comunica com o repositório
 * diretamente.
 *
 * -> Que restrições podem ter cada auction?
 *
 * -> Cada cliente tem que ter um id único que o identifique, para que cada auction possa
 * estar associada ao cliente que a criou. Este id tem que ser passado ao servidor no json,
 * por exemplo: jsonObject.put("creatorid", id);
 *
 * -> Um cliente não pode terminar uma auction que não foi criada por ele mesmo.
 *
 * -> Como implementar os multi clientes?
 *
 * -> Como tratamos cada bid numa auction? O json pode ter vários campos com o mesmo id
 * (neste caso vários valores para bid)? E podemos associar cada bid a cada cliente que a fez?
 * É relevante não para os clientes, mas para o servidor para depois ser possível determinar
 * quem fez a maior bid.
 *
 * -> Será interessante haver outra forma de terminar uma auction para além de esta terminar
 * apenas quando o seu criador a termine? Por exemplo haver um timer.
 *
 * -> Uma action pode ter um campo de description, para ser mais fácil a identificação de cada
 * auction (por exemplo, uma auction de quê em concreto). y
 *
 * -> Quando uma bid é criada tem de ser resolvido um criptopuzzle. y
 *
 * -> As bids são mandadas para o repositório, depois é validado pelo manager, e depois volta
 * para o repositório.
 * 
 * Cifração e decifração com chaves públicas e privadas.
 * MAC
 * SHA
 * Cartão de Cidadão
 * 
 * 
 * cliente faz bid e assina, repositório recebe bid e assina, manager valida e assina (ISTO FORMA A RECEIPT)
 * 
 */

public class AuctionClient {

	static Scanner sc = new Scanner(System.in);
	static String line = "";
	static int clientid;
	private static Key publicKey;
	private static Key privateKey;
	private static SecretKey secKey = null;
	private static Key managerPublicKey = null;
	private static Key repositoryPublicKey = null;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void executeCommand(int action) {
		try {
			if (action == 1) {
				createAuction();
			}
			else if(action == 2) {
				terminateAuction();
			}
			else if (action == 3) {
				listAuctions();
			}
			else if(action == 4) {
				bidOnAuction();
			}
			else if(action == 5) {
				displayBids();
			}
			else if (action == 0) {
				System.exit(0);
			}
		} catch(Exception e) {
			
		}
	}
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		//Generate public and private keys
		generateKeys();

		//Set name for this client
		System.out.println("Welcome to our Auction Application!");
		System.out.print("Please enter your name: ");
		String name = sc.next();

		//Connection to the servers
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		InetAddress ia = InetAddress.getLocalHost();
		data.put("action", "newclient");
		data.put("name", name);
		String encodedKey = encoder.encodeToString(publicKey.getEncoded());
		data.put("clientkey", encodedKey);
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 8000);
		DatagramPacket dp0 = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from manager server
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jsonObject = new JSONObject(response);
		clientid = jsonObject.getInt("clientid");
		managerPublicKey = getKey(jsonObject.getString("manpubkey"));

		//Response from repository server
		ds.send(dp0);
		byte[] b2 = new byte[1024];
		DatagramPacket dp2 = new DatagramPacket(b2, b2.length);
		ds.receive(dp2);
		String response1 = new String(dp2.getData());
		JSONObject jsonObject2 = new JSONObject(response1);
		repositoryPublicKey = getKey(jsonObject2.getString("reppubkey"));
		
		//Create file for this client
		File f = new File("Receipts/client" + response + ".txt");

		while(true) {
			int action = menu();
			executeCommand(action);
		}
	}

	//Create a new auction
	public static void createAuction() throws IOException {
		//Auction creation
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		System.out.println("\n - AUCTION CREATION - \n");
		System.out.println("Please describe what you are auctioning: ");
		System.out.print("> ");
		String description = sc.next();

		//Auction restrictions
		System.out.println("\nWhat type of auction do you wish to create?");
		System.out.println("1 - Ascending price auction");
		System.out.println("2 - Blind auction");
		System.out.print("> ");
		int type = sc.nextInt();
		if(type == 1)
			data.put("type", "ascending");
		else if(type == 2) {
			System.out.println("\nDo you want the bidders to be public or private?");
			System.out.println("1 - Public");
			System.out.println("2 - Private");
			System.out.print("> ");
			int identity = sc.nextInt();
			if(identity == 1)
				data.put("identity", "public");
			else if(identity == 2)
				data.put("identity", "private");
			else
				return;
			data.put("type", "blind");
		}
		else
			return;

		//Send data to manager
		Date timestamp = new Date();
		data.put("timestamp", timestamp);
		data.put("description", description);
		data.put("action", "create");
		data.put("creatorid", clientid);
		JSONArray arr = new JSONArray();
		arr.put(0);
		data.put("bid", arr);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 8000);
		ds.send(dp);
	}

	//List all auctions
	public static void listAuctions() throws IOException {
		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "list");
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}
	
	//List auctions from other clients
	public static void listOthersAuctions() throws IOException {
		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "listothers");
		data.put("creatorid", clientid);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}
	
	//List auctions from this client
	public static void listMyAuctions() throws IOException {
		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "listmine");
		data.put("creatorid", clientid);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}

	//Terminate an auction
	public static void terminateAuction() throws IOException {
		//List auctions from this client
		listMyAuctions();

		//Send data to repository
		System.out.println("Which auction do you wish to terminate?");
		System.out.print("> ");
		int choice = sc.nextInt();
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("creatorid", clientid);
		data.put("action", "terminate");
		data.put("position", choice);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);
	}
	
	//Bid on an active auction
	public static void bidOnAuction() throws IOException {
		//List auctions from other clients
		listOthersAuctions();

		//Request to create new bid
		DatagramSocket ds = new DatagramSocket();
		JSONObject bid = new JSONObject();
		bid.put("action", "bid");
		bid.put("bidder", clientid);
		byte[] bidb = bid.toString().getBytes();
		InetAddress ia1 = InetAddress.getLocalHost();
		DatagramPacket dp2 = new DatagramPacket(bidb, bidb.length, ia1, 9000);
		ds.send(dp2);

		//Cryptopuzzle
		byte[] resp = new byte[1024];
		DatagramPacket respp = new DatagramPacket(resp, resp.length);
		ds.receive(respp);
		String r = new String(respp.getData());
		JSONObject jo = new JSONObject(r);
		int difficulty = jo.getInt("difficulty");
		String comparison = "";
		for(int i = 0; i < difficulty; i++) {
			comparison += "0";
		}	
		String hash = "";
		hash = calculateHash(jo.getString("arg1"), jo.getString("arg2"));
		while(hash.substring(0, difficulty).equals(comparison)) {		
			hash = calculateHash(jo.getString("arg1"), jo.getString("arg2"));
		}
		byte[] cipheredhash = cipherAES(hash.getBytes());
		byte[] cipheredkey = cipherRSA(secKey.getEncoded(), repositoryPublicKey);
		JSONObject hashjson = new JSONObject();
		hashjson.put("action", "bid");
		hashjson.put("hash", cipheredhash.toString());
		hashjson.put("key", cipheredkey.toString());
		byte[] send = hashjson.toString().getBytes();
		InetAddress ia3 = InetAddress.getLocalHost();
		DatagramPacket dp3 = new DatagramPacket(send, send.length, ia1, 9000);
		ds.send(dp3);

		//finally
		byte[] byte1 = new byte[1024];
		DatagramPacket dpac = new DatagramPacket(byte1, byte1.length);
		ds.receive(dpac);

		//Bid creation
		JSONObject data1 = new JSONObject();
		System.out.println("\nTo which auction do you wish to bid?");
		System.out.print("> ");
		int choice = sc.nextInt();
		System.out.println("Value: ");
		System.out.print("> ");
		int value = sc.nextInt();
		Date timestamp = new Date();
		data1.put("creatorid", clientid);
		data1.put("timestamp", timestamp);
		data1.put("action", "bidcont");
		data1.put("auction", choice);
		data1.put("value", value);

		//Send data to repository
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data1.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}
	
	//Display all bids of an auction
	public static void displayBids() throws IOException {
		//List all auctions
		listAuctions();

		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		System.out.println("\nChoose an auction.");
		System.out.print("> ");
		int choice = sc.nextInt();
		Date timestamp = new Date();
		data.put("timestamp", timestamp);
		data.put("creatorid", clientid);
		data.put("action", "showbids");
		data.put("auction", choice);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}

	public static int menu() {
		System.out.println("\n-----------------------------------\n");
		System.out.println("What would you like to do?");
		System.out.println("1 - Create an auction.");
		System.out.println("2 - Terminate an auction.");
		System.out.println("3 - List open and closed auctions.");
		System.out.println("4 - Bid on an auction.");
		System.out.println("5 - Display all current bids of an auction.");
		System.out.println("6 - Display all bids sent by a client.");
		System.out.println("7 - Check the outcome of an auction where you have participated.");
		System.out.println("8 - Check a receipt.");
		System.out.println("0 - Exit.");
		System.out.print("Enter your choice: ");
		int choice = sc.nextInt();
		return choice;
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

	//Calculate hash
	public static String calculateHash(String s1, String s2) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String input = s1 + s2;
			md.update(input.getBytes());
			byte[] digest = md.digest();
			StringBuffer sb = new StringBuffer();
			for(byte b : digest) {
				sb.append(String.format("%02x", b & 0xff));
			}
			return sb.toString();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	//Cipher with symmetric key
	static byte[] cipherAES(byte[] in) {
		try {
			Cipher aesCipher = Cipher.getInstance("AES");
			aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
			return aesCipher.doFinal(in);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	//Cipher with public key
	static byte[] cipherRSA(byte[] in, Key key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(in);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	//Decipher with private key
	static byte[] decipherRSA(byte[] in, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
	    cipher.init(Cipher.DECRYPT_MODE, key);  
	    return cipher.doFinal(in);
	}
}
