import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;
import org.json.JSONObject;

public class AuctionManager implements Runnable {
	
	public static int client = 0;

	public void run() {
		
	}
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
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
}
