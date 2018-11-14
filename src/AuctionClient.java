import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

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
 */

public class AuctionClient implements Runnable {

	static Scanner sc = new Scanner(System.in);
	static String line = "";
	static List<JSONObject> test = new ArrayList<JSONObject>();
	static String clientid;

	public void run() {
		
	}
	
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
	
	public static void main(String[] args) throws IOException {
		//NEW CLIENT CONNECTION
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		InetAddress ia = InetAddress.getLocalHost();
		data.put("action", "newclient");
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 8000);
		ds.send(dp);
		//RESPONSE FROM REPOSITORY
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		clientid = response;
		clientid = clientid.replace("\u0000", "");
		//CREATES A FILE FOR THIS CLIENT
		File f = new File("Receipts/client" + response + ".txt");
		System.out.println("Welcome to our Auction Client!");
		System.out.println("You are the client number " + response + "!");
		while(true) {
			int action = menu();
			executeCommand(action);
		}
	}

	//CREATES A NEW AUCTION
	public static void createAuction() throws IOException {
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		System.out.println("\n - AUCTION CREATION - \n");
		System.out.println("Please describe what you are auctioning: ");
		System.out.print("> ");
		String description = sc.next();
		//RESTRICTIONS OF AN AUCTION	
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
		Date timestamp = new Date();
		data.put("timestamp", timestamp);
		data.put("description", description);
		data.put("action", "create");
		data.put("creatorid", clientid);
		JSONArray arr = new JSONArray();
		arr.put(0);
		data.put("bid", arr);
		System.out.println(data);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 8000);
		ds.send(dp);
	}

	//LISTS ALL EXISTING AUCTIONS
	public static void listAuctions() throws IOException {
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "list");
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);
		//RESPONSE FROM REPOSITORY
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}
	
	//LISTS ALL AUCTIONS FROM OTHER CLIENTS
	public static void listOthersAuctions() throws IOException {
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "listothers");
		data.put("creatorid", clientid);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);
		//RESPONSE FROM REPOSITORY
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}
	
	//LISTS ALL AUCTIONS FROM THIS CLIENT
	public static void listMyAuctions() throws IOException {
		DatagramSocket ds = new DatagramSocket();
		JSONObject data = new JSONObject();
		data.put("action", "listmine");
		data.put("creatorid", clientid);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);
		//RESPONSE FROM REPOSITORY
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}

	//TERMINATES AN AUCTION
	public static void terminateAuction() throws IOException {
		listMyAuctions();
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
	
	//BID ON AN EXISTING AUCTION
	public static void bidOnAuction() throws IOException {
		listOthersAuctions();
		DatagramSocket ds = new DatagramSocket();
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
		data1.put("action", "bid");
		data1.put("auction", choice);
		data1.put("value", value);
		InetAddress ia = InetAddress.getLocalHost();
		byte[] b = data1.toString().getBytes();
		DatagramPacket dp = new DatagramPacket(b, b.length, ia, 9000);
		ds.send(dp);
		//RESPONSE FROM THE SERVER
		byte[] b1 = new byte[1024];
		DatagramPacket dp1 = new DatagramPacket(b1, b1.length);
		ds.receive(dp1);
		String response = new String(dp1.getData());
		System.out.println(response);
	}
	
	//DISPLAY ALL BIDS OF A CHOSEN AUCTION
	public static void displayBids() throws IOException {
		listAuctions();
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
		//RESPONSE FROM REPOSITORY
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
}
