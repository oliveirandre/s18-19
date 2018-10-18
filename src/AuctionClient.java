import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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

public class AuctionClient {

	static Scanner sc = new Scanner(System.in);
	static OutputStreamWriter writer;
	static BufferedReader reader;
	static Socket s;
	static String line = "";
	static List<JSONObject> test = new ArrayList<JSONObject>();

	public static void main(String[] args) throws IOException {
		System.out.println("Welcome to our Auction Client!");

		s = new Socket("localhost", 8080);
		writer = new OutputStreamWriter(s.getOutputStream(), "UTF-8");
		reader = new BufferedReader(new InputStreamReader(s.getInputStream(), "UTF-8"));

		JSONObject data = new JSONObject();
		data.put("action" , "newClient");
		writer.write(data.toString() + "\n");
		writer.flush();
		line = reader.readLine();
		System.out.println("És o utilizador numero:  "  + line);

		while(true) {
			s = new Socket("localhost", 8080);
			writer = new OutputStreamWriter(s.getOutputStream(), "UTF-8");
			reader = new BufferedReader(new InputStreamReader(s.getInputStream(), "UTF-8"));

			int action = menu();
			if (action == 1) {
				createAuction();
			}
			else if (action == 3) {
				listAuctions();
			}
			else if (action == 0) {
				s.close();
				System.exit(0);
			}
		}
	}

	public static void createAuction() throws IOException {
		JSONObject data = new JSONObject();

		System.out.println("\n - AUCTION CREATION - \n");
		System.out.println("Please describe what you are auctioning: ");
		System.out.print("> ");
		String description = sc.next();

		//restrições da auction
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
		//envio dos dados para o servidor
		writer.write(data.toString() + "\n");
		writer.flush();

		//recebimento dos dados enviados pelo servidor
		line = reader.readLine();
		JSONObject response = new JSONObject(line);

		//test.add(data);

		System.out.println("\nAuction created sucessfuly: \n" + response);

		//readCommand();
	}

	public static void listAuctions() throws IOException {
		JSONObject data = new JSONObject();
		data.put("action", "list");

		writer.write(data.toString() + "\n");
		writer.flush();

		String auctions = reader.readLine();
		//JSONObject response = new JSONObject(auctions);

		System.out.println(auctions);
	}

	public static void terminateAuction() throws IOException {
		JSONObject data = new JSONObject();
		data.put("action", "terminate");
	}

	public static int menu() {
		System.out.println("\n-----------------------------------\n");
		System.out.println("What would you like to do?");
		System.out.println("1 - Create an auction.");
		System.out.println("2 - Terminate an auction.");
		System.out.println("3 - List open and closed auctions.");
		System.out.println("4 - Display all current bids of an auction.");
		System.out.println("5 - Display all bids sent by a client.");
		System.out.println("6 - Check the outcome of an auction where you have participated.");
		System.out.println("7 - Check a receipt.");
		System.out.println("0 - Exit.");
		System.out.print("Enter your choice: ");
		int choice = sc.nextInt();
		return choice;
	}
}
