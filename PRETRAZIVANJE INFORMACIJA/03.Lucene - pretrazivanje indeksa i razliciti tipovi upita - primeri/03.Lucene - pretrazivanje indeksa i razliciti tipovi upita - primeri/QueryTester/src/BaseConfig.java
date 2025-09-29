import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;

/**
 * Sadrži analizator koji je zajednički za indeksiranje i pretragu 
 * i konstante sa nazivima polja i putanjama do podataka i indeksa. 
 */
public class BaseConfig {
	public static final String DIREKTORIJUM_SA_PODACIMA = "Podaci";
	public static final String DIREKTORIJUM_SA_INDEKSOM = "Indeks";

	public static final String POLJE_PUTANJA = "putanja";
	public static final String POLJE_SADRZAJ = "sadrzaj";
	public static final String POLJE_NASLOV = "naslov";
	public static final String POLJE_VELICINA_STRING = "velicina_string";
	public static final String POLJE_VELICINA_LONG = "velicina_long";
	
	// Analizator se čuva ovde da bi isti analizator bio dostupan i za indeksiranje 
	// i za pretraživanje
	protected Analyzer analyzer;
	
	public BaseConfig() {
		this.analyzer = new StandardAnalyzer();
	}
}
