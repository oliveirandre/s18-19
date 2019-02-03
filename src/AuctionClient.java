import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.StringCharacterIterator;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.security.MessageDigest;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.lang.model.util.ElementScanner6;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.NoSuchProviderException;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.BufferedInputStream;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/*
 *
 * -> Que restrições podem ter cada auction?
 *
 * -> Será interessante haver outra forma de terminar uma auction para além de esta terminar
 * apenas quando o seu criador a termine? Por exemplo haver um timer.
 *
 * MAC
 * SHA
 * Cartão de Cidadão
 * 
 * 
 * cliente faz bid e assina, repositório recebe bid e assina, manager valida e assina (ISTO FORMA A RECEIPT)
 * 
 */

public class AuctionClient {

	private static Scanner sc = new Scanner(System.in);
	private static int seq = 1;
	private static String name;
	private static KeyPair kp;
	private static SecretKey mansession = null;
	private static SecretKey repsession = null;
	private static Key managerPublicKey = null;
	private static Key repositoryPublicKey = null;
	private static byte[] toSign = null;
	private static int bidnumber = 1;
	//private static CC cc;
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
				String s = listAuctions();
				if(s.equals("")) {
					System.out.println("\nNo available auctions.");
				}
				else {
					System.out.println(s);
				}
			}
			else if(action == 4) {
				bidOnAuction();
			}
			else if(action == 5) {
				displayBids();
			}
			else if(action == 6) {
				bidsByClient();
			}
			else if(action == 7) {
				checkOutcome();
			}
			else if(action == 8) {
				receipt();
			}
			else if (action == 0) {
				System.exit(0);
			}
		} catch(Exception e) {
			
		}
	}
	
	public static void main(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException {
		//Generate public and private keys
		/*
		try {
			cc = new CC();
		} catch (Exception e) {
			System.err.print(e);
			return;
		}
		*/
		generateKeys();

		//Set name for this client
		System.out.println(" - Welcome to our Auction Application! - ");
		System.out.print("\nPlease enter your name: ");
		name = sc.nextLine();

		//Connection to the servers
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		InetAddress ia = InetAddress.getLocalHost();
		data.put("action", "newclient");
		//data.put("name", name);
		data.put("seq", seq);
		//String encodedKey = encoder.encodeToString(publicKey.getEncoded());
		//data.put("clientkey", encodedKey);
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 8000);
		ds.send(dp);

		//Response from manager server
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jsonObject = new JSONObject(response);
		checkseq(jsonObject.getInt("seq"));
		FileInputStream fis = new FileInputStream(jsonObject.getString("path"));
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate c = (X509Certificate) cf.generateCertificate(fis);
		managerPublicKey = c.getPublicKey();

		//send ciphered data to manager
		data.remove("seq");
		data.put("seq", seq);
		byte[] bytes = name.getBytes();
		byte[] cipheredname = cipherAES(bytes, mansession);
		byte[] cipheredkey = cipherRSA(mansession.getEncoded(), managerPublicKey);
		data.put("creatorid", encoder.encodeToString(cipheredname));
		data.put("key", encoder.encodeToString(cipheredkey));
		byte[] databytes = data.toString().getBytes();
		DatagramPacket d = new DatagramPacket(databytes, databytes.length, ia, 8000);
		ds.send(d);

		//Data to repository
		data.remove("seq");
		data.remove("creatorid");
		data.remove("key");
		data.put("seq", seq);
		byte[] b3 = data.toString().getBytes();
		DatagramPacket dp0 = new DatagramPacket(b3, b3.length, ia, 9000);
		ds.send(dp0);

		//Response from repository
		byte[] b2 = new byte[1024];
		DatagramPacket dp2 = new DatagramPacket(b2, b2.length);
		ds.receive(dp2);
		String response1 = new String(dp2.getData());
		JSONObject jsonObject2 = new JSONObject(response1);
		checkseq(jsonObject2.getInt("seq"));
		FileInputStream fis2 = new FileInputStream(jsonObject2.getString("path"));
		CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
		X509Certificate c2 = (X509Certificate) cf2.generateCertificate(fis2);
		repositoryPublicKey = c2.getPublicKey();

		byte[] bytes2 = name.getBytes();
		byte[] cipheredname2 = cipherAES(bytes2, repsession);
		byte[] cipheredkey2 = cipherRSA(repsession.getEncoded(), repositoryPublicKey);
		data.remove("seq");
		data.put("seq", seq);
		data.put("creatorid", encoder.encodeToString(cipheredname2));
		data.put("key", encoder.encodeToString(cipheredkey2));
		byte[] databytes2 = data.toString().getBytes();
		DatagramPacket d2 = new DatagramPacket(databytes2, databytes2.length, ia, 9000);
		ds.send(d2);

		byte[] by = new byte[1024];
		DatagramPacket pack = new DatagramPacket(by, by.length);
		ds.receive(pack);
		String s = new String(pack.getData());
		//System.out.println(s);
		JSONObject jo = new JSONObject(s);
		checkseq(jo.getInt("seq"));
		if(jo.getInt("ack") == 1) {
			System.out.println("\nConnection established!");
		}
		else {
			return;
		}

		//Create file for this client
		//File f = new File("Receipts/client" + response + ".txt");

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
		System.out.println("\nName of the auction: ");
		System.out.print("> ");
		String aucname = sc.nextLine();
		System.out.println("\nPlease describe what you are auctioning: ");
		System.out.print("> ");
		String description = sc.nextLine();

		//Auction restrictions
		System.out.println("\nWhat type of auction do you wish to create?");
		System.out.println("1 - Ascending price auction");
		System.out.println("2 - Blind auction");
		System.out.print("> ");
		if(sc.hasNextInt()) {
			int type = sc.nextInt();
			sc.nextLine();
			if(type == 1) {
				data.put("type", "ascending");
			}
			else if(type == 2) {
				data.put("type", "blind");
			}
			else {
				System.out.println("\nInvalid option!");
				return;
			}

			System.out.print("Minimum Bid ->");
			int minBid = sc.nextInt();
			data.put("minBid", String.valueOf(minBid));
			System.out.print("Max Bids per user ->");
			int maxBid = sc.nextInt();
			data.put("maxBids", String.valueOf(maxBid));



		}
		else {
			System.out.println("\nInvalid option!");
			String error = sc.next();
			return;
		}

		byte[] cipheredcreator = cipherAES(name.getBytes(), mansession);
		data.put("creatorid", encoder.encodeToString(cipheredcreator));

		//Send data to manager
		Date timestamp = new Date();
		data.put("timestamp", timestamp);
		data.put("description", description);
		data.put("name", aucname);
		data.put("action", "create");
		data.put("seq", seq);
		JSONArray arr = new JSONArray();
		arr.put(0);
		data.put("bid", arr);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 8000);
		ds.send(dp);

		//Response from manager
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jo = new JSONObject(response);
		if(jo.getInt("ack") == 1 && checkseq(jo.getInt("seq"))) {
			System.out.println("\nAuction created successfully!");
		}
	}

	//List all auctions
	public static String listAuctions() throws IOException {
		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "list");
		data.put("seq", seq);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jo = new JSONObject(response);
		checkseq(jo.getInt("seq"));
		return jo.getString("list");
	}
	
	//List auctions from other clients
	public static String listOthersAuctions() throws IOException {
		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "listothers");
		data.put("seq", seq);
		byte[] cipheredcreator = cipherAES(name.getBytes(), mansession);
		data.put("creatorid", encoder.encodeToString(cipheredcreator));
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jo = new JSONObject(response);
		checkseq(jo.getInt("seq"));
		return jo.getString("list");
	}
	
	//List auctions from this client
	public static String listMyAuctions() throws IOException {
		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "listmine");
		data.put("seq", seq);
		byte[] bytes = name.getBytes();
		byte[] cipheredcreator = cipherAES(bytes, mansession);
		data.put("creatorid", encoder.encodeToString(cipheredcreator));		
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jo = new JSONObject(response);
		checkseq(jo.getInt("seq"));
		return jo.getString("list");
	}

	//Terminate an auction
	public static void terminateAuction() throws IOException {
		//List auctions from this client
		String s = listMyAuctions();
		if(s.equals("")) {
			System.out.println("\nYou have no auctions to terminate!");
			return;
		}
		System.out.println(s);
		
		//Send data to repository
		System.out.println("\nWhich auction do you wish to terminate?");
		System.out.print("> ");
		int choice = sc.nextInt();
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		byte[] bytes = name.getBytes();
		byte[] cipheredcreator = cipherAES(bytes, mansession);
		data.put("creatorid", encoder.encodeToString(cipheredcreator));
		data.put("seq", seq);
		data.put("action", "terminate");
		data.put("position", choice);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		//Response from repository
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jo = new JSONObject(response);
		if(checkseq(jo.getInt("seq")) && jo.getInt("ack") == 1) {
			System.out.println("\nAuction terminated successfully!");
		}
		else
			System.out.println("\nCouldn't terminate the auction.");
	}
	
	//Bid on an active auction
	public static void bidOnAuction() throws SignatureException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException {
		//List auctions from other clients
		String s = listOthersAuctions();
		if(s.equals("")) {
			System.out.println("\nNo available auctions to bid.");
			return;
		}
		else
			System.out.println(s);

		//Request to create new bid
		DatagramSocket ds = new DatagramSocket();
		JSONObject bid = new JSONObject();
		bid.put("action", "bid");
		bid.put("seq", seq);
		byte[] bidb = bid.toString().getBytes();
		InetAddress ia1 = InetAddress.getLocalHost();
		DatagramPacket dp2 = new DatagramPacket(bidb, bidb.length, ia1, 9000);
		ds.send(dp2);

		//Cryptopuzzle and bid fields
		byte[] resp = new byte[1024];
		DatagramPacket respp = new DatagramPacket(resp, resp.length);
		ds.receive(respp);
		System.out.println("\nSolving cryptopuzzle...");
		String r = new String(respp.getData());
		JSONObject jo = new JSONObject(r);
		checkseq(jo.getInt("seq"));
		int difficulty = jo.getInt("difficulty");
		String comparison = "";
		for(int i = 0; i < difficulty; i++) {
			comparison += "0";
		}	
		String hash = "";
		int var = 0;
		hash = calculateHash(jo.getString("action"), jo.getInt("seq"), var); 
		while(!(hash.substring(0, difficulty).equals(comparison))) {		
			var++;
			hash = calculateHash(jo.getString("action"), jo.getInt("seq"), var);
		}
		//System.out.println(hash);
		byte[] cipheredhash = cipherAES(hash.getBytes(), repsession);
		byte[] cipheredkey = cipherRSA(repsession.getEncoded(), repositoryPublicKey);
		JSONObject hashjson = new JSONObject();
		hashjson.put("action", "bid");
		hashjson.put("bidnumber", bidnumber);
		hashjson.put("seq", seq);
		hashjson.put("hash", encoder.encodeToString(cipheredhash));
		hashjson.put("key", encoder.encodeToString(cipheredkey));
		//System.out.println(encoder.encodeToString(secKey.getEncoded()));
		//System.out.println(hashjson.toString());
		System.out.println("\nTo which auction do you wish to bid?");
		System.out.print("> ");
		int choice = sc.nextInt();
		System.out.println("\nValue (must be an integer): ");
		System.out.print("> ");
		if(sc.hasNextInt()) {
			int value = sc.nextInt();
			hashjson.put("error", 0);
			String val = String.valueOf(value);
			byte[] bytesvalue = val.getBytes();
			byte[] cipheredvalue = cipherAES(bytesvalue, mansession);
			hashjson.put("value", encoder.encodeToString(cipheredvalue));
		}
		else {
			System.out.println("\nInvalid bid value.");
			String error = sc.next();
			hashjson.put("error", 1);
			byte[] send = hashjson.toString().getBytes();
			InetAddress ia3 = InetAddress.getLocalHost();
			DatagramPacket dp3 = new DatagramPacket(send, send.length, ia3, 9000);
			ds.send(dp3);
			return;
		}
		Date timestamp = new Date();
		byte[] cipheredkey2 = cipherRSA(mansession.getEncoded(), managerPublicKey);
		byte[] bytes = name.getBytes();
		byte[] cipheredcreator = cipherAES(bytes, mansession);
		hashjson.put("creatorid", encoder.encodeToString(cipheredcreator));
		hashjson.put("key2", encoder.encodeToString(cipheredkey2));
		hashjson.put("timestamp", timestamp);
		hashjson.put("auction", choice);
		//toSign = hashjson.toString().getBytes();


		/*PrintWriter pw = new PrintWriter("Receipts/bid.txt");
		pw.println("bid");
		pw.close();

		//sign the bid
		/*Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
		dsa.initSign(kp.getPrivate());

		FileInputStream fis = new FileInputStream("Receipts/bid.txt");
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
			dsa.update(buffer, 0, len);
		};
		bufin.close();

		byte[] signatureBytes = dsa.sign();
		FileOutputStream sigfos = new FileOutputStream("Receipts/" + encoder.encodeToString(cipheredcreator) + bidnumber + ".txt");
		sigfos.write(signatureBytes);
		sigfos.close();*/

		//hashjson.put("toSign", toSign.toString());

		//hashjson.put("signature", signatureBytes.toString());

		/*
		dsa.initVerify(kp.getPublic());
		dsa.update(sign);
		*/

		/*FileInputStream fis = new FileInputStream(args[0]);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
			dsa.update(buffer, 0, len);
		};
		bufin.close();
		byte[] realSig = dsa.sign();*/

		/* save the signature in a file */
		/*FileOutputStream sigfos = new FileOutputStream("sig");
		sigfos.write(realSig);
		sigfos.close();

		/* save the public key in a file */
		/*byte[] key = publicKey.getEncoded();
		FileOutputStream keyfos = new FileOutputStream("manepk");
		keyfos.write(key);
		keyfos.close();*/

		//send cryptopuzzle and bid to repository
		byte[] send = hashjson.toString().getBytes();
		InetAddress ia3 = InetAddress.getLocalHost();
		DatagramPacket dp3 = new DatagramPacket(send, send.length, ia3, 9000);
		ds.send(dp3);
		
		//final response from repository
		byte[] byte1 = new byte[1024];
		DatagramPacket dpac = new DatagramPacket(byte1, byte1.length);
		ds.receive(dpac);
		String r1 = new String(dpac.getData());
		JSONObject jo2 = new JSONObject(r1);
		if(jo2.getInt("ack") == 0) {
			System.out.println("\nInvalid auction.");
		}
		else if(checkseq(jo2.getInt("seq")) && jo2.getInt("ack") == 1) {
			System.out.println("\nBid sent succesfully");
			bidnumber++;
		}
		else if(jo2.getInt("ack") == 2) {
			System.out.println("\nBid is inferior to the previous one!");
		}
		else if(jo2.getInt("ack") == 3) {
			System.out.println("\nMax Bids amount already reached!");
		}



	}
	
	//Display all bids of an auction
	public static void displayBids() throws IOException {
		//List all auctions
		String s = listAuctions();
		if(s.equals("")) {
			System.out.println("\nNo available auctions.");
			return;
		}
		else {
			System.out.println(s);
		}

		//Send data to repository
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		System.out.println("\nChoose an auction.");
		System.out.print("> ");
		int choice = sc.nextInt();
		Date timestamp = new Date();
		data.put("timestamp", timestamp);
		data.put("seq", seq);
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
		JSONObject jsonObject = new JSONObject(response);
		checkseq(jsonObject.getInt("seq"));
		if(jsonObject.get("bids").equals("none"))
			System.out.println("Can't show bids of a blind auction!");
		else {
			System.out.println(jsonObject.get("bids"));
		}
	}

	public static void checkOutcome() throws IOException {
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		byte[] bytes = name.getBytes();
		byte[] cipheredcreator = cipherAES(bytes, mansession);
		//byte[] cipheredkey2 = cipherRSA(mansession.getEncoded(), managerPublicKey);
		data.put("creatorid", encoder.encodeToString(cipheredcreator));
		//data.put("key", encoder.encodeToString(cipheredkey2));
		data.put("seq", seq);
		data.put("action", "checkoutcome");
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);

		byte[] b1 = new byte[2048];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jsonObject = new JSONObject(response);
		checkseq(jsonObject.getInt("seq"));
		if(jsonObject.get("options").equals("")) {
			System.out.println("\nYou haven't put a bid on an auction.");
			return;
		}
		System.out.println(jsonObject.get("options"));

		JSONObject data1 = new JSONObject();
		System.out.println("\nWhich auction do you wish to check?");
		System.out.print("> ");
		int choice = sc.nextInt();
		data1.put("bidder", encoder.encodeToString(cipheredcreator));
		data1.put("seq", seq);
		data1.put("action", "checkcont");
		data1.put("auction", choice);

		byte[] b2 = data1.toString().getBytes();
		DatagramPacket dp2 = new DatagramPacket(b2, b2.length, ia, 8000);
		ds.send(dp2);

		//Response from repository
		byte[] b3 = new byte[1024];
		DatagramPacket dp3 = new DatagramPacket(b3, b3.length);
		ds.receive(dp3);
		String line = new String(dp3.getData());
		JSONObject jo = new JSONObject(line);
		if(checkseq(jo.getInt("seq"))) {
			System.out.println("\n" + jo.get("winner"));
		}
	}

	public static void bidsByClient() throws IOException {
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		byte[] bytes = name.getBytes();
		byte[] cipheredcreator = cipherAES(bytes, mansession);
		data.put("creatorid", encoder.encodeToString(cipheredcreator));
		data.put("seq", seq);
		data.put("action", "bidsbyclient");
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 8000);
		ds.send(dp);

		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		JSONObject jsonObject = new JSONObject(response);
		checkseq(jsonObject.getInt("seq"));
		System.out.println(jsonObject.get("options"));

		JSONObject data1 = new JSONObject();
		System.out.println("Which client do you wish to check?");
		System.out.print("> ");
		int choice = sc.nextInt();
		data1.put("creatorid", encoder.encodeToString(cipheredcreator));
		data1.put("action", "clientcont");
		data1.put("seq", seq);
		data1.put("client", choice);
		byte[] b2 = data1.toString().getBytes();
		DatagramPacket dp2 = new DatagramPacket(b2, b2.length, ia, 8000);
		ds.send(dp2);

		byte[] b3 = new byte[1024];
		DatagramPacket dp3 = new DatagramPacket(b3, b3.length);
		ds.receive(dp3);
		String line = new String(dp3.getData());
		JSONObject jo = new JSONObject(line);
		if(checkseq(jo.getInt("seq"))) {
			if(jo.get("bids").equals(""))
				System.out.println("\nThe client has made no bids.");
			else 
				System.out.println("\n" + jo.get("bids"));
		}
	}

	private static void receipt() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IOException, SignatureException {
	
		// ----- VERIFY

		byte[] bytes = name.getBytes();
		byte[] cipheredcreator = cipherAES(bytes, mansession);
		FileInputStream sigfis = new FileInputStream("Receipts/" + encoder.encodeToString(cipheredcreator) + bidnumber + ".txt");
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify);
		sigfis.close();

		System.out.println("read signature successfully");

		Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
		sig.initVerify(kp.getPublic());
		FileInputStream datafis = new FileInputStream("Receipts/bid.txt");
		BufferedInputStream bufin2 = new BufferedInputStream(datafis);

		System.out.println("read data successfully");

		byte[] buffer2 = new byte[1024];
		int len2;
		while (bufin2.available() != 0) {
			len2 = bufin2.read(buffer2);
			sig.update(buffer2, 0, len2);
		};
		bufin2.close();

		boolean verifies = sig.verify(sigToVerify);
		System.out.println("signature verifies: " + verifies);
	}

	public static int menu() {
		System.out.println("\n-----------------------------------\n");
		System.out.println("What would you like to do?");
		System.out.println("1 - Create an auction.");
		System.out.println("2 - Terminate an auction.");
		System.out.println("3 - List open and closed auctions.");
		System.out.println("4 - Bid on an auction.");
		System.out.println("5 - Display all bids of an auction.");
		System.out.println("6 - Display all bids sent by a client.");
		System.out.println("7 - Check the outcome of an auction where you have participated.");
		System.out.println("8 - Check a receipt.");
		System.out.println("0 - Exit.");
		System.out.print("Enter your choice: ");
		int choice = sc.nextInt();
		sc.nextLine();
		return choice;
	}
	
	//Generate public and private keys
	static void generateKeys() throws NoSuchAlgorithmException {
		//AES - Symmetric Key		
		KeyGenerator man = KeyGenerator.getInstance("AES");
		man.init(128); // The AES key size in number of bits
		mansession = man.generateKey();

		KeyGenerator rep = KeyGenerator.getInstance("AES");
		rep.init(128); // The AES key size in number of bits
		repsession = rep.generateKey();

		//RSA - Public and Private Keys
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		kp = kpg.generateKeyPair();
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
	public static String calculateHash(String s1, int s2, int in) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String input = s1 + s2 + in;
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
	static byte[] cipherAES(byte[] in, SecretKey key) {
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

	static boolean checkseq(int i) {
		//System.out.println(i + " - " + seq);
		if(i == seq + 1) {
			seq++;
			return true;
		}
		else {
			System.out.println("Connection compromised! Exiting...");
			System.exit(0);
			return false;
		}
	}
}
