import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

public class AuctionManager {
	
	static List<JSONObject> auctions = new ArrayList<JSONObject>();
	
	public static void main(String[] args) throws IOException {
		ServerSocket ss = new ServerSocket(8080);
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
					
					if(jsonObject.get("action") == "create") {
						auctions.add(jsonObject);
					}
					else if(jsonObject.get("action") == "list") {
						for(int i = 0; i < auctions.size(); i++)
							System.out.println(auctions.get(i));
					}
					
					writer.write(jsonObject.toString() + "\n");
					writer.flush();
				} catch (IOException e) {
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
