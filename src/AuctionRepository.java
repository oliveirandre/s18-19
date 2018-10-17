import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

public class AuctionRepository {

	static List<JSONObject> auctions = new ArrayList<JSONObject>();
	
	public static void main(String[] args) throws IOException {

	}

	public void store(JSONObject auction) throws IOException {
		auctions.add(auction);
		
	}
	
	public List<JSONObject> list() throws IOException {
		return auctions;
	}	
}
