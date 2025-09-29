import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.search.similarities.BM25Similarity;
import org.apache.lucene.search.similarities.ClassicSimilarity;
import org.apache.lucene.search.similarities.Similarity;

public class BaseConfig {
	public static final String DIREKTORIJUM_SA_PODACIMA = "Podaci";
	public static final String DIREKTORIJUM_SA_INDEKSOM = "Indeks";

	public static final String POLJE_PUTANJA = "putanja";
	public static final String POLJE_SADRZAJ = "sadrzaj";
	public static final String POLJE_NASLOV = "naslov";
	public static final String POLJE_VELICINA_STRING = "velicina_string";
	public static final String POLJE_VELICINA_LONG = "velicina_long";
	

	protected Analyzer analyzer;
	protected Similarity similarity;
	
	public BaseConfig() {
		this.analyzer = new StandardAnalyzer();
		this.similarity= new BM25Similarity();
		//this. similarity = new ClassicSimilarity();

	}
}
