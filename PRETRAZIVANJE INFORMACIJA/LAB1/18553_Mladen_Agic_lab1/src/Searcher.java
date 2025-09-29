import java.io.IOException;
import java.nio.file.Paths;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.StoredFields;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.WildcardQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.BooleanClause.Occur;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;


public class Searcher extends BaseConfig implements AutoCloseable {
	private Directory directory;
	private IndexReader indexReader;
	private IndexSearcher indexSearcher;
	private QueryParser classicParser;

	public Searcher(String indexDirPath) throws IOException {
		this.directory = FSDirectory.open(Paths.get(indexDirPath));
		this.indexReader = DirectoryReader.open(directory);
		this.indexSearcher = new IndexSearcher(indexReader);

		this.classicParser = new QueryParser(POLJE_SADRZAJ, this.analyzer);
														
	}

	@Override
	public void close() throws Exception {
		this.indexReader.close();
		this.directory.close();
	}

	private void parseClassicAndSearch(String stringQuery) {
		System.out.println();
		System.out.println("\"Classic\" parser parsira upit: " + stringQuery);
		try {
			Query query = this.classicParser.parse(stringQuery);
			System.out.println("Pretraživanje po parsiranom objektu: '" + query 
					+ "' tipa " + query.getClass().getName());
			findAndShowResults(query);
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}


	private void searchIndex(Query query) {
		System.out.println();
		System.out.println("Pretraživanje po objektu klase query: '" + query 
				+ "' tipa " + query.getClass().getName());
		this.findAndShowResults(query);
	}

	private void findAndShowResults(Query query) {
		try {
			TopDocs hits = indexSearcher.search(query, 10);
			System.out.println("Broj pogodaka: " + hits.totalHits.value);

			StoredFields storedFields = indexReader.storedFields();
			for (ScoreDoc scoreDoc : hits.scoreDocs) {
				Document document = storedFields.document(scoreDoc.doc);
				String path = document.get(POLJE_PUTANJA);
				System.out.println("Pronađeni fajl je: " + path);
			}
		} catch (IOException ioException) {
			ioException.printStackTrace();
		}
	}

	public void BooleanQueries1() {

		TermQuery term1 = new TermQuery(new Term(POLJE_SADRZAJ, "vermin")); // bez prefiksa
		TermQuery term2 = new TermQuery(new Term(POLJE_SADRZAJ, "Alice")); // mora biti prisutan
		TermQuery term3 = new TermQuery(new Term(POLJE_SADRZAJ, "Dogstar")); // termin se mora iskljuciti


		BooleanQuery.Builder builder = new BooleanQuery.Builder();


		builder.add(term1,Occur.SHOULD); // OR
		builder.add(term2,Occur.MUST); // AND
		builder.add(term3,Occur.MUST_NOT); // NOT
		

		BooleanQuery query = builder.build();

		searchIndex(query);

	
	}
	public void BooleanQueries2() {

		String queryStr = "vermin +Alice -Dogstar";
		QueryParser parser = new QueryParser(POLJE_SADRZAJ, analyzer);
		try {
		    Query parsedQuery = parser.parse(queryStr);
		    searchIndex(parsedQuery);	
		} catch (ParseException e) {
		    e.printStackTrace();
		}
	
	}
	
	public void WildcardQueries() throws Exception {
		WildcardQuery wildcardQuery1 = new WildcardQuery(new Term(POLJE_SADRZAJ, "travel*"));
		searchIndex(wildcardQuery1);
		parseClassicAndSearch(POLJE_SADRZAJ + ":travel*");
	}


	
	

	
}
