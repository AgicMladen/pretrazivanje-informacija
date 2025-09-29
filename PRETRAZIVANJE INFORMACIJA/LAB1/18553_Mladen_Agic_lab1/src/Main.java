import java.io.File;

public class Main {

	public static void main(String[] args) {
	
		

		FileSplitter.main(null); 

		Indexer indexer = new Indexer();

		System.out.println("Kreiranje prvog indeksa (originalna 4 fajla)...");
		indexer.createIndex(BaseConfig.DIREKTORIJUM_SA_PODACIMA, BaseConfig.DIREKTORIJUM_SA_INDEKSOM);
		System.out.println("Veličina indeksa: " +
				calculateFolderSize(new File(BaseConfig.DIREKTORIJUM_SA_INDEKSOM)) + " bajtova");

		System.out.println("\nKreiranje drugog indeksa (400 fajlova)...");
		indexer.createIndex(BaseConfig.DIREKTORIJUM_SA_PODELJENIM_PODACIMA, BaseConfig.DIREKTORIJUM_SA_DRUGIM_INDEKSOM);
		System.out.println("Veličina indeksa: " +
				calculateFolderSize(new File(BaseConfig.DIREKTORIJUM_SA_DRUGIM_INDEKSOM)) + " bajtova");
		
		  try {
		        System.out.println("Pretraga nad prvim indeksom:");
		        try (Searcher searcher = new Searcher(BaseConfig.DIREKTORIJUM_SA_INDEKSOM)) {
		            searcher.BooleanQueries1();
		            searcher.BooleanQueries2();
		            searcher.WildcardQueries();
		        }

		        System.out.println("\nPretraga nad drugim indeksom:");
		        try (Searcher searcher = new Searcher(BaseConfig.DIREKTORIJUM_SA_DRUGIM_INDEKSOM)) {
		            searcher.BooleanQueries1();
		            searcher.BooleanQueries2();
		            searcher.WildcardQueries();
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
