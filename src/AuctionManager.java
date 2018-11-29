import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.json.JSONObject;
import java.util.Base64;

public class AuctionManager {
	
	public static int client = 0;
	private static String pubKey;
	private static Key prv;
	static Base64.Encoder encoder = Base64.getEncoder();
	static Base64.Decoder decoder = Base64.getDecoder();
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		generateKeys();	
		
		//KEY EXCHANGE BETWEEN SERVERS
		DatagramSocket ds1 = new DatagramSocket();
		JSONObject data = new JSONObject();
		InetAddress ia = InetAddress.getLocalHost();
		data.put("action", "serverconnection");
		data.put("pubkey", pubKey);
		System.out.println(pubKey);
		byte[] b1 = data.toString().getBytes();
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, 9000);
		ds1.send(dp1);		

		DatagramSocket ds = new DatagramSocket(8000);
		while(true) {
			byte[] b = new byte[1024];
			DatagramPacket dp = new DatagramPacket(b, b.length);
			ds.receive(dp);
			String line = new String(dp.getData());
			JSONObject jsonObject = new JSONObject(line);
			readCommand(jsonObject, dp, ds);
		}
	}

	static void readCommand(JSONObject jsonObject, DatagramPacket dp, DatagramSocket ds) throws IOException {
		//ESTABLISHES THE ID OF A NEW CLIENT
		if(jsonObject.get("action").equals("newclient")) {
			System.out.println("New client connecting!");
			client++;
			BufferedWriter writer = new BufferedWriter(new FileWriter("Receipts/client" + client + ".txt"));
			writer.write("Client connected sucessfuly!\n");
			writer.close();
			byte[] b1 = String.valueOf(client).getBytes();
			InetAddress ia = InetAddress.getLocalHost();
			DatagramPacket dp1 = new DatagramPacket(b1, b1.length, ia, dp.getPort());
			ds.send(dp1);
		}
		
		//CREATE A NEW AUCTION
		if(jsonObject.get("action").equals("create")) {
			BufferedWriter writer = new BufferedWriter(new FileWriter("Receipts/client" + jsonObject.getString("creatorid") + ".txt", true));
			writer.append(jsonObject.toString() + "\n");
			writer.close();
			System.out.println(jsonObject.toString());
			DatagramSocket ds1 = new DatagramSocket();
			InetAddress ia = InetAddress.getLocalHost();
			byte[] b = jsonObject.toString().getBytes();
			DatagramPacket dp1 = new DatagramPacket(b, b.length, ia, 9000);
			ds1.send(dp1);
		}
		
		//NEW BID
		if(jsonObject.get("action").equals("bid")) {
			BufferedWriter writer = new BufferedWriter(new FileWriter("Receipts/client" + jsonObject.getString("creatorid") + ".txt", true));
			writer.append(jsonObject.toString() + "\n");
			writer.close();
		}
	}
	
	static void generateKeys() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Key pub = kp.getPublic();
		Key pvt = kp.getPrivate();		
		//String outFile = "private";
		pubKey = encoder.encodeToString(pub.getEncoded());
		//Writer out = new FileWriter(outFile + ".key");
		//out.write(encoder.encodeToString(pvt.getEncoded()));
		//out.close();
	}
}
