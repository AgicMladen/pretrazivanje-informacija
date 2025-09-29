import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.LongPoint;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.IndexWriterConfig.OpenMode;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.tika.Tika;


public class Indexer extends BaseConfig {

	public void createIndex(String dataFolderPath, String indexFolderPath) {
		long startTime = System.currentTimeMillis();

		IndexWriterConfig config = new IndexWriterConfig(this.analyzer);
		config.setOpenMode(OpenMode.CREATE);
		
		Tika tika = new Tika();

		try (Directory indexDir = FSDirectory.open(Paths.get(indexFolderPath));
			 IndexWriter indexWriter = new IndexWriter(indexDir, config)) {

			File dataDir = new File(dataFolderPath);
			File[] files = dataDir.listFiles();
			int count = 0;

			for (File file : files) {
				Document document = new Document();
				String title = file.getName();
				String titleWithoutExtension = title.substring(0, title.length() - 4);

				document.add(new StringField(POLJE_PUTANJA, file.getCanonicalPath(), Field.Store.YES));
				document.add(new TextField(POLJE_NASLOV, titleWithoutExtension, Field.Store.YES));
				document.add(new StringField(POLJE_VELICINA_STRING, String.valueOf(file.length()), Field.Store.YES));
				document.add(new LongPoint(POLJE_VELICINA_LONG, file.length()));
				document.add(new TextField(POLJE_SADRZAJ, tika.parse(file)));
				//document.add(new TextField(POLJE_SADRZAJ, new FileReader(file)));
				indexWriter.addDocument(document);
				count++;
			}

			long endTime = System.currentTimeMillis();
			long duration = endTime - startTime;

			System.out.println("Indeksirano " + count + " fajlova.");
			System.out.println("Vreme indeksiranja: " + duration + " ms");

			long size = calculateFolderSize(new File(indexFolderPath));
			System.out.println("Veličina indeksa: " + size + " bajtova");

		}
		catch (IOException ioException) {
			ioException.printStackTrace();
		}
	}

	// Metoda za izračunavanje veličine direktorijuma
	private long calculateFolderSize(File folder) {
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


