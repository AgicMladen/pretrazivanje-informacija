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
import org.apache.lucene.search.BoostQuery;
import org.apache.lucene.search.Explanation;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.BooleanClause.Occur;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;


public class Searcher extends BaseConfig implements AutoCloseable {
	private Directory directory;
	private IndexReader indexReader;
	private IndexSearcher indexSearcher;


	public Searcher(String indexDirPath) throws IOException {
		this.directory = FSDirectory.open(Paths.get(indexDirPath));
		this.indexReader = DirectoryReader.open(directory);
		this.indexSearcher = new IndexSearcher(indexReader);

		this.indexSearcher.setSimilarity(similarity);	
	}

	@Override
	public void close() throws Exception {
		this.indexReader.close();
		this.directory.close();
	}
	

	private void searchIndex(Query query) {
		System.out.println();
		System.out.println("Pretraživanje po objektu klase query: '" + query 
				+ "' tipa " + query.getClass().getName());
		this.findAndShowResults(query);
	}

	// 3.
	private void findAndShowResults(Query query) {
	    try {
	        TopDocs hits = indexSearcher.search(query, 10);
	        System.out.println("Broj pogodaka: " + hits.totalHits.value);

	        StoredFields storedFields = indexReader.storedFields();
	        for (int i = 0; i < hits.scoreDocs.length; i++) {
	            ScoreDoc scoreDoc = hits.scoreDocs[i];
	            Document document = storedFields.document(scoreDoc.doc);
	            String path = document.get(POLJE_PUTANJA);

	            System.out.println("=======================================");
	            System.out.println("Pronađeni fajl broj " + (i + 1) + ": " + path);
	            System.out.println("Score: " + scoreDoc.score);


	            Explanation explanation = indexSearcher.explain(query, scoreDoc.doc);
	            System.out.println("Objašnjenje score vrednosti:");
	            System.out.println(explanation.toString());
	        }
	    } catch (IOException ioException) {
	        ioException.printStackTrace();
	    }
	}
	

	public void BooleanQueries1() {

		TermQuery termNaslov1 = new TermQuery(new Term(POLJE_NASLOV, "alices"));
		TermQuery termNaslov2 = new TermQuery(new Term(POLJE_NASLOV, "wonderland"));

		
		TermQuery termSadrzaj1 = new TermQuery(new Term(POLJE_SADRZAJ, "alices"));
		TermQuery termSadrzaj2 = new TermQuery(new Term(POLJE_SADRZAJ, "wonderland"));
		
		
		BooleanQuery.Builder sadrzajBuilder = new BooleanQuery.Builder();
		sadrzajBuilder.add(termSadrzaj1, Occur.SHOULD);
		sadrzajBuilder.add(termSadrzaj2, Occur.SHOULD);
		BooleanQuery sadrzajQuery = sadrzajBuilder.build();

		BooleanQuery.Builder naslovBuilder = new BooleanQuery.Builder();
		naslovBuilder.add(termNaslov1, Occur.SHOULD);
		naslovBuilder.add(termNaslov1, Occur.SHOULD);
		BooleanQuery naslovQuery = naslovBuilder.build();
		
		// Dodavanje boost-a
		double classicBoostsadrzaj = 64.067;
		double bmBoostnaslov = 1.503553883836547163989377581106;
		Query boostedSadrzajQuery = new BoostQuery(sadrzajQuery, 64.067f);
		System.out.println("----- Rezultati za polje SADRZAJ -----");
		searchIndex(sadrzajQuery);
		//searchIndex(sadrzajQuery);
		
		// Dodavanje boost-a
		Query boostedNaslovQuery = new BoostQuery(naslovQuery, 1.503553883836547163989377581106f);
		System.out.println("----- Rezultati za polje NASLOV -----");
		//searchIndex(boostedNaslovQuery);
		searchIndex(naslovQuery);
		
		// Dodavanje boost-a
		System.out.println("----- Rezultati za polje SADRZAJ SA BOOSTOM-----");
		searchIndex(boostedSadrzajQuery);
		//searchIndex(sadrzajQuery);
				
		// Dodavanje boost-a
		System.out.println("----- Rezultati za polje NASLOV SA BOOSTOM-----");
		//searchIndex(boostedNaslovQuery);
		searchIndex(boostedNaslovQuery);
		
	}
	
	public void BooleanQueries2() {
		
		String queryStr = "Alice Wonderland";
		QueryParser sadrzajParser = new QueryParser(POLJE_SADRZAJ, analyzer);
		QueryParser naslovParser = new QueryParser(POLJE_NASLOV, analyzer);
		try {
		    Query sadrzajQuery1 = sadrzajParser.parse(queryStr);
		    Query naslovQuery1 = naslovParser.parse(queryStr);
		    
	        float boostFactorN = 6.357178863195506858904066579115f;
	        Query naslovQuery2 = new BoostQuery(naslovQuery1, boostFactorN);
	        
	        
	        float boostFactoS = 1;
	        Query sadrzajQuery2 = new BoostQuery(sadrzajQuery1, boostFactoS);
		    
		    
		    System.out.println("----- Rezultati za polje SADRZAJ -----");
		    searchIndex(sadrzajQuery1);
		    
		    System.out.println("----- Rezultati za polje NASLOV -----");
		    searchIndex(naslovQuery1);
		    
		    System.out.println("----- Rezultati za polje SADRZAJ SA BOOSTOM -----");
		    searchIndex(sadrzajQuery2);
		    
		    System.out.println("----- Rezultati za polje NASLOV SA BOOSTOM-----");
		    searchIndex(naslovQuery2);
		    
		    
		} catch (ParseException e) {
		    e.printStackTrace();
		}

	
	}

}
