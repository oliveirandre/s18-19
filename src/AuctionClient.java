import java.net.Socket;
import java.util.ArrayList;
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
 * auction (por exemplo, uma auction de quê em concreto).
 *
 * -> Quando uma bid é criada tem de ser resolvido um criptopuzzle.
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
			/*else {
				s.close();
				System.exit(0);
			}*/
		}
	}

	public static void createAuction() throws IOException {
		JSONObject data = new JSONObject();

		//tipo de ação
		data.put("action", "create");

		//restrições da auction

		//envio dos dados para o servidor
		writer.write(data.toString() + "\n");
		writer.flush();

		//recebimento dos dados enviados pelo servidor
		line = reader.readLine();
		JSONObject response = new JSONObject(line);

		//test.add(data);

		System.out.println("Auction created sucessfuly: \n" + response);

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
		System.out.println("Welcome to our Auction Client!");
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
