import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

public class AuctionManager {

	static AuctionRepository ar = new AuctionRepository();
	static List<JSONObject> test;
	static Blockchain blockChain;
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		ServerSocket ss = new ServerSocket(8080);						
		blockChain = new Blockchain(); 
		System.out.println("Genesis Block Hash: \n" + blockChain.getLatestBlock().hash);
		test = new ArrayList<JSONObject>();
		try {
			while(true) {
				Socket s = ss.accept();
				startHandler(s);
			}
		} finally {
			ss.close();
		}
	}

	private static void startHandler(Socket s) throws IOException {
		Thread t = new Thread() {
			@Override
			public void run() {
				try {
					OutputStreamWriter writer = new OutputStreamWriter(s.getOutputStream(), "UTF-8");
					BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream(), "UTF-8"));
					String line = reader.readLine();
					JSONObject jsonObject = new JSONObject(line);
					
					if(jsonObject.get("action").equals("create")) {
 						test.add(jsonObject);
 						
 						System.out.println("\nMining block...");
 						blockChain.addBlock(new Block(1, jsonObject.toString(), jsonObject.get("timestamp").toString() , ""));
 						System.out.println("Previous block: " + blockChain.getLatestBlock().previousHash);
 						writer.write(jsonObject.toString() + "\n");
 						writer.flush();
					}
					
					else if(jsonObject.get("action").equals("list")) {
						
						System.out.println(test.size());
						for(int i=0; i<test.size();i++) {
							writer.append(test.get(i).toString());

						}
						writer.write(test.get(0).toString());
						writer.flush();
					}

				} catch (IOException e) {
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} finally {
					closeSocket();
				}
			}

			private void closeSocket() {
				try {
					s.close();
				} catch(IOException e) {

				}
			}
		};
		t.start();
	}
}
