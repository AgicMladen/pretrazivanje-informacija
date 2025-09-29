import java.io.File;
import java.io.FileReader;
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

/**
 * Klasa koje služi samo da kreira indeks.
 *
 */
public class Indexer extends BaseConfig {

	/**
	 * Metoda za kreiranje indeksa.
	 */
	public void createIndex() {
		IndexWriterConfig config = new IndexWriterConfig(this.analyzer);
		config.setOpenMode(OpenMode.CREATE);

		// Koristi se try-with-resources konstrukcija da bi se otvoreni resursi sigurno
		// zatvorili u slučaju da dođe do nekog izuzetka.
		try (Directory indexDir = FSDirectory.open(Paths.get(DIREKTORIJUM_SA_INDEKSOM));
				IndexWriter indexWriter = new IndexWriter(indexDir, config);) {
			File dataDir = new File(DIREKTORIJUM_SA_PODACIMA);
			File[] files = dataDir.listFiles();
			for (File file : files) {
				Document document = new Document();
				String title = file.getName();
				String titleWithoutExtension = title.substring(0, title.length() - 4);
				document.add(new StringField(POLJE_PUTANJA, file.getCanonicalPath(), Field.Store.YES));
				document.add(new TextField(POLJE_NASLOV, titleWithoutExtension, Field.Store.YES));
				document.add(
						new StringField(POLJE_VELICINA_STRING, Long.valueOf(file.length()).toString(), Field.Store.YES));
				document.add(new LongPoint(POLJE_VELICINA_LONG, file.length()));
				// veličinu dokumenta u bajtovima smo upamtili na 2 načina -
				// kao standardno string polje i kao long polje koje će nam omogućiti
				// bržu pretragu po vrednosti
				document.add(new TextField(POLJE_SADRZAJ, new FileReader(file)));

				indexWriter.addDocument(document);
			}
		} catch (IOException ioException) {
			ioException.printStackTrace();
		}
	}

}
