import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;


public class BaseConfig {
	public static final String DIREKTORIJUM_SA_PODACIMA = "Podaci";
	public static final String DIREKTORIJUM_SA_INDEKSOM = "Indeks";
	

	public static final String POLJE_PUTANJA = "putanja";
	public static final String POLJE_SADRZAJ = "sadrzaj";
	public static final String POLJE_NASLOV = "naslov";
	public static final String POLJE_VELICINA_STRING = "velicina_string";
	public static final String POLJE_VELICINA_LONG = "velicina_long";
	

	protected Analyzer analyzer;
	
	public BaseConfig() {
		this.analyzer = new StandardAnalyzer();
	}
}
