import java.io.File;

public class Main {

	public static void main(String[] args) {
		

		Indexer indexer = new Indexer();

		System.out.println("Kreiranje prvog indeksa (originalna 4 fajla)...");
		indexer.createIndex(BaseConfig.DIREKTORIJUM_SA_PODACIMA, BaseConfig.DIREKTORIJUM_SA_INDEKSOM);
		System.out.println("Veličina indeksa: " +
		calculateFolderSize(new File(BaseConfig.DIREKTORIJUM_SA_INDEKSOM)) + " bajtova");
	
		  try {
		        try (Searcher searcher = new Searcher(BaseConfig.DIREKTORIJUM_SA_INDEKSOM)) {
		           searcher.BooleanQueries1();
		           // searcher.BooleanQueries2();

		        }

		    } catch (Exception e) {
		        e.printStackTrace();
		  }

	}
	private static long calculateFolderSize(File folder) {
		long length = 0;
		File[] files = folder.listFiles();
		if (files != null) {
			for (File file : files) {
				if (file.isFile())
					length += file.length();
				else
					length += calculateFolderSize(file);
			}
		}
		return length;
	}
	

}
