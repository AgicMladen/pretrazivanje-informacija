import java.io.IOException;
import java.nio.file.Paths;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.Map;

import org.apache.lucene.document.Document;
import org.apache.lucene.document.LongPoint;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.StoredFields;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.queryparser.flexible.core.QueryNodeException;
import org.apache.lucene.queryparser.flexible.standard.StandardQueryParser;
import org.apache.lucene.queryparser.flexible.standard.config.PointsConfig;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.FuzzyQuery;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.PhraseQuery;
import org.apache.lucene.search.PrefixQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TermRangeQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.WildcardQuery;
import org.apache.lucene.search.BooleanClause.Occur;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;

/**
 * Klasa za testiranje različitih načina pretraživanja indeksa.
 *
 */
public class Searcher extends BaseConfig implements AutoCloseable {
	private Directory directory;
	private IndexReader indexReader;
	private IndexSearcher indexSearcher;

	// Potrebna su nam 2 parsera za upite:
	// Običan (classic) parser upita koji služi za parsiranje velike većine upita,
	// ali ne može da parsira upite nad Point poljima.
	private QueryParser classicParser;
	// Novija implementacija parsera, standardni (flexible) parser upita koji ćemo
	// da koristimo za Point upite.
	private StandardQueryParser pointQueryParser;

	/**
	 * Konstruktor koji inicijalizuje sve pomoćne objekte potrebne za pretraživanje
	 * indeksa.
	 */
	public Searcher() throws IOException {
		this.directory = FSDirectory.open(Paths.get(DIREKTORIJUM_SA_INDEKSOM));
		this.indexReader = DirectoryReader.open(directory); // 3
		this.indexSearcher = new IndexSearcher(indexReader);

		this.classicParser = new QueryParser(POLJE_SADRZAJ, this.analyzer); // default polje za pretraživanje je
																			// "sadržaj"

		this.pointQueryParser = new StandardQueryParser(this.analyzer);
		// U konfiguraciji za standardni parser moramo da zadamo nazive polja koja su
		// zadata kao Point polja i da ih mapiramo na odgovarajući numerički tip.
		Map<String, PointsConfig> map = new HashMap<String, PointsConfig>();
		map.put(POLJE_VELICINA_LONG, new PointsConfig(NumberFormat.getInstance(), Long.class));
		pointQueryParser.setPointsConfigMap(map);
	}

	@Override
	public void close() throws Exception {
		// Klase implementira interfejs AutoCloseable da bi se automatizovalo zatvaranje
		// resursa koji se koriste za pretraživanje.
		this.indexReader.close();
		this.directory.close();
	}
	
	/**
	 * Parsira upit "classic" parserom i izvršava ga. 
	 * @param stringQuery Upit zadat u tekstualnom obliku. 
	 */
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

	/**
	 * Parsira upit "standard" parserom za point podatke i izvršava ga.
	 * @param stringQuery Upit zadat u tekstualnom obliku.
	 * @param fieldName "Standard" parseru se obavezno prosleđuje i naziv 
	 * polja za pretraživanje. 
	 */
	private void parsePointAndSearch(String stringQuery, String fieldName) {
		System.out.println();
		System.out.println("\"Point\" parser parsira upit: " + stringQuery);
		try {
			Query query = this.pointQueryParser.parse(stringQuery, fieldName);
			System.out.println("Pretraživanje po parsiranom objektu: '" + query 
					+ "' tipa " + query.getClass().getName());
			findAndShowResults(query);
		} catch (QueryNodeException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Radi pretraživanje indeksa na osnovu objektnog modela upita {@code query}. 
	 * Prethodno prikazuje taj objektni model upita.  
	 * @param query Objektni model upita predstavljen nekom od klasa izvedenih 
	 * iz {@link Query}. 
	 */
	private void searchIndex(Query query) {
		System.out.println();
		System.out.println("Pretraživanje po objektu klase query: '" + query 
				+ "' tipa " + query.getClass().getName());
		this.findAndShowResults(query);
	}

	/**
	 * Pretražuje indeks na osnovu objektnog modela upita {@code query} pa zatim 
	 * prikazuje pronađene dokumente.   
	 * @param query Objektni model upita predstavljen nekom od klasa izvedenih 
	 * iz {@link Query}. 
	 */
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

	
	/**
	 * 1. Testiranje upita sa jednim terminom.
	 */
	public void testTermQueries() {
		// Najpre se kreira objekat klase Term kome se zadaju polje u kome se 
		// pretražuje i tekst koji se traži. Pošto se termin kreira direktno 
		// (bez propuštanja teksta kroz analizator) mora da bude zadat 
		// ISKLJUČIVO MALIM SLOVIMA.
		// Zatim se kreira od tog termina upit tipa TermQuery. 
		TermQuery termQuery = new TermQuery(new Term(POLJE_SADRZAJ, "hamlet"));
		// Izvršava se upit tipa TermQuery. 
		searchIndex(termQuery);
		
		// Naredni upit radi isto kao i prethodni, ali se kreira kroz parser.  
		// Zato ovaj upit nije case sensitive pošto "prolazi" kroz analizator 
		// koji prebacuje sve termine u mala slova.
		parseClassicAndSearch("HaMleT");

		// Još primera za TermQuery
		parseClassicAndSearch("Ophelia");
		parseClassicAndSearch("Anna");
	}
	
	/**
	 * 2. Testiranje upita sa logičkim operatorima.
	 */
	public void testBooleanQueries() {
		// Logički operatori se zadaju isključivo velikim slovima: 
		// AND, OR, NOT
		parseClassicAndSearch("Hamlet AND Ophelia");
		parseClassicAndSearch("hamlet AND ophelia"); // radi isto što i prethodni

		// Isti upit kao i prethodni samo zadat direktno preko objekata.
		// Ovde "ručno" kreiramo objektni model za pretragu.
		// Kreira se BooleanQuery koji sarži 2 TermQuery objekta.
		TermQuery termHamlet = new TermQuery(new Term(POLJE_SADRZAJ, "hamlet"));
		TermQuery termOphelia = new TermQuery(new Term(POLJE_SADRZAJ, "ophelia"));
		BooleanQuery.Builder booleanQueryBuilder = new BooleanQuery.Builder();
		booleanQueryBuilder.add(termHamlet, Occur.MUST);
		booleanQueryBuilder.add(termOphelia, Occur.MUST);
		// Occur.MUST specificira da pronađeni dokumenti
		// MORAJU da sadrže navedeni termin (logički AND operator).
		//
		// Moguće vrednosti su još i Occur.SHOULD i Occur.MUST_NOT.
		//
		// Occur.MUST_NOT specificira da pronađeni dokumenti NE MOGU
		// da sadrže navedeni termin (logički NOT operator).
		//
		// Occur.SHOULD specificira da pronađeni dokumenti mogu da sadrže
		// da sadrže navedeni termin, ali je moguće da se među tim dokumentima
		// nađu neki koji ne sadrže taj termin (ako upit ima više termina pa
		// su ti dokumenti pronađeni preko drugih termina) (logički OR operator).
		BooleanQuery booleanQuery = booleanQueryBuilder.build();
		searchIndex(booleanQuery);

		// Umesto AND, OR, NOT kod tekstualnih upita mogu da se koriste 
		// i operatori + ili - pišu se direktno uz termin koji se traži. 
		// Značenje je sledeće:
		// + se prevodi u Occur.MUST
		// - se prevodi u Occur.MUST_NOT
		// ako nema znaka + ni - podrazumeva se Occur.SHOULD 
		parseClassicAndSearch("+Hamlet Ophelia");
		// kako bi se prethodni upit preveo u objektni model: Hamlet=>Occur.MUST,
		// Ophelia=>Occur.SHOULD
		parseClassicAndSearch("Hamlet +Ophelia"); // Hamlet=>Occur.SHOULD, Ophelia=>Occur.MUST

		parseClassicAndSearch("hamlet anna"); // Hamlet=>Occur.SHOULD, Anna=>Occur.SHOULD
		parseClassicAndSearch("Hamlet OR Anna"); // Hamlet=>Occur.SHOULD, Anna=>Occur.SHOULD

		// Naredni upit daje isti rezultat kao i prethodna 2 upita
		TermQuery termAnna = new TermQuery(new Term(POLJE_SADRZAJ, "anna"));
		booleanQueryBuilder = new BooleanQuery.Builder();
		booleanQueryBuilder.add(termHamlet, Occur.SHOULD);
		booleanQueryBuilder.add(termAnna, Occur.SHOULD);
		searchIndex(booleanQueryBuilder.build());

		// Primer upita sa Not operatorom
		// Znak minus ima isto značenje kao i operator NOT
		// samo što mora da se piše direktno ispred termina bez blanko znaka
		parseClassicAndSearch("Anna NOT Hamlet"); // Anna=>Occur.SHOULD, Hamlet=>Occur.MUST_NOT
		parseClassicAndSearch("Anna -Hamlet"); // Anna=>Occur.SHOULD, Hamlet=>Occur.MUST_NOT

		// moguće je kombinovati bulovske upite sa nazivima polja
		parseClassicAndSearch(POLJE_NASLOV + ":Anna");
		parseClassicAndSearch("Hamlet NOT " + POLJE_NASLOV + ":Hamlet");
		parseClassicAndSearch("Hamlet -" + POLJE_NASLOV + ":Hamlet");
		
		
		// Logički upit sa 3 termina 
		parseClassicAndSearch("anna OR hamlet AND ophelia");
		// Isti upit kreiran preko objektnog modela. 
		booleanQueryBuilder = new BooleanQuery.Builder();
		booleanQueryBuilder.add(termAnna, Occur.SHOULD);
		booleanQueryBuilder.add(termHamlet, Occur.MUST);
		booleanQueryBuilder.add(termOphelia, Occur.MUST);
		searchIndex(booleanQueryBuilder.build());
	}

	/**
	 * 3. Testiranje upita nad opsegom stringova.
	 */
	public void testTermRangeQueries() {
		// Upit po terminima u opsegu radi tako što termine u indeksu posmatra kao
		// leksikografski sortirane tj. sortirane u rastućem redosledu ako bi se 
		// međusobno poredili funkcijom String.compareTo.

		// Parametri funkcije newStringRange za kreiranje upita su:
		// 1. naziv polja u kome se radi pretraživanje
		// 2. donja granica opsega
		// 3. gornja granica opsega
		// naredni parametri definišu da li je interval pretrage otvoren ili zatvoren 
		// 4. true - donja granica opsega je uključena, false - nije uključena
		// 5. true - gornja granica opsega je uključena, false - nije uključena
		TermRangeQuery termRangeQuery1 = TermRangeQuery.newStringRange(POLJE_NASLOV, 
				"anna", "idiot", true, true);
		searchIndex(termRangeQuery1);
		// Isti upit zadat tekstualno, parsiran QueryParser-om pa onda izvršen. Granice
		// opsega, kada su uključene u rezultate pretrage se zadaju uglastim zagradama [].
		parseClassicAndSearch(POLJE_NASLOV + ":[Anna TO Idiot]");
		// Upite izvršavamo nad poljem "naslov" koje ima samo 8 termina da bismo lakše
		// protumačili rezultate. Termini iz polja "naslov" (uređeni leksikografski) su:
		// and, anna, hamlet, idiot, karenina, peace, the, war

		// Upit sa isključenom gornjom granicom:
		TermRangeQuery termRangeQuery2 = TermRangeQuery.newStringRange(POLJE_NASLOV, 
				"anna", "idiot", true, false);
		searchIndex(termRangeQuery2);
		// Ako upit zadajemo tekstualno granica koja je isključena se zadaje vitičastom
		// zagradom {}
		parseClassicAndSearch(POLJE_NASLOV + ":[Anna TO Idiot}");

		// Upit sa isključene obe granice
		TermRangeQuery termRangeQuery3 = TermRangeQuery.newStringRange(POLJE_NASLOV, 
				"anna", "idiot", false, false);
		searchIndex(termRangeQuery3);
		// Ako upit zadajemo tekstualno granica koja je isključena se zadaje vitičastom
		// zagradom {}
		parseClassicAndSearch(POLJE_NASLOV + ":{Anna TO Idiot}");

		// Ako želimo da upit ne bude ograničen sa gornje strane odgovarajućem parametru
		// se prosleđuje null
		TermRangeQuery termRangeQuery4 = TermRangeQuery.newStringRange(POLJE_NASLOV, 
				"karenina", null, true, true);
		searchIndex(termRangeQuery4);
		// U tekstualnom upitu se umesto nedostajućeg parametra stavlja *
		parseClassicAndSearch(POLJE_NASLOV + ":[Karenina TO *]");

		// Upit koji nije ograničen sa donje strane
		TermRangeQuery termRangeQuery5 = TermRangeQuery.newStringRange(POLJE_NASLOV, 
				null, "hamlet", false, false);
		searchIndex(termRangeQuery5);
		// U tekstualnom upitu se umesto nedostajućeg parametra stavlja *
		parseClassicAndSearch(POLJE_NASLOV + ":{* TO hamlet}");

		// Polje "velicina_string" smo kreirali kao polje tipa String i tako će se
		// ponašati i prilikom pretrage. To polje predstavlja veličinu svakog od 
		// dokumenata u bajtovima i ima samo 4 termina: 1425227, 2041122, 210708, 3359550. 
		// Ti termini su u ovom redosledu leksikografski sortirani jer ih Lucene 
		// posmatra kao stringove. Tako će i naredni upiti da se izvršavaju kao nad 
		// stringovima i to objašnjava vraćene rezultate.
		TermRangeQuery termRangeQuery6 = TermRangeQuery.newStringRange(POLJE_VELICINA_STRING, 
				"0", "30", true, true);
		searchIndex(termRangeQuery6);
		// Isti upit u tekstualnom formatu
		parseClassicAndSearch(POLJE_VELICINA_STRING + ":[0 TO 30]");
	}

	/**
	 * 4. Testiranje upita nad opsegom numeričkih podataka (point).
	 */
	public void testPointRangeQueries() {
		// Upit sa opsegom - range query kad je vrednost sačuvana u binarnom formatu.
		// Nad ovakvim poljima upit dosta brže radi. Vrednosti polja se posmatraju 
		// kao numeričke i rezultat upita se razlikuje od TermRangeQuery kada se 
		// vrednosti polja posmatraju kao stringovi.
		Query pointRangeQuery1 = LongPoint.newRangeQuery(POLJE_VELICINA_LONG, 0, 30);
		searchIndex(pointRangeQuery1);
		// Isti upit u tekstualnom formatu
		parsePointAndSearch(POLJE_VELICINA_LONG + ":[0 TO 30]", POLJE_VELICINA_LONG);

		// Upit koji vraća rezultate
		Query pointRangeQuery2 = LongPoint.newRangeQuery(POLJE_VELICINA_LONG, 0, 1425227);
		searchIndex(pointRangeQuery2);
		// Isti upit u tekstualnom formatu
		parsePointAndSearch(POLJE_VELICINA_LONG + ":[0 TO 1425227]", POLJE_VELICINA_LONG);

		// Kada se upit zadaje kreiranjem objekta granice opsega su uvek inkluzivne i ne 
		// postoji način da se one isključe iz rezultata pretrage (osim da se 
		// inkrementiraju/dekrementiraju).
		// Kod tekstualnog upita moguće je zadati ekskluzivne granice korišćenjem
		// vitičastih zagrada { i }.
		parsePointAndSearch(POLJE_VELICINA_LONG + ":[0 TO 1425227}", POLJE_VELICINA_LONG);
	
		// Kroz objektni model je moguće zadati i upit sa tačnom vrednošću.
		Query pointRangeQuery3 = LongPoint.newExactQuery(POLJE_VELICINA_LONG, 3359550);
		searchIndex(pointRangeQuery3);

		// Kroz objektni model je moguće zadati i upit nad skupom vrednosti.
		Query pointRangeQuery4 = LongPoint.newSetQuery(POLJE_VELICINA_LONG, 3359550, 210708);
		searchIndex(pointRangeQuery4);
		
		// Ako želimo da upit ne bude ograničen sa gornje strane onda sa te strane 
		// treba da postavimo maksimalnu vrednost za zadati tip podataka. 
		Query pointRangeQuery5 = LongPoint.newRangeQuery(POLJE_VELICINA_LONG, 1425227, Long.MAX_VALUE);
		searchIndex(pointRangeQuery5);
	}

	/**
	 * 5. Testiranje upita sa zadatim prefiksima.
	 */
	public void testPrefixQueries() {

		// Naredni upit vraća sve dokumente koji sadrže termine koji počinju sa "hamle"
		PrefixQuery prefixQuery1 = new PrefixQuery(new Term(POLJE_SADRZAJ, "hamle"));
		searchIndex(prefixQuery1);
		
		// Tekstualni format prefix upita treba da se završava znakom zvezdica *
		// * označava od 0 do više karaktera (slično kao u jeziku regularnih izraza)
		parseClassicAndSearch("HamLe*");
		
		PrefixQuery prefixQuery2 = new PrefixQuery(new Term(POLJE_SADRZAJ, "leo"));
		searchIndex(prefixQuery2);
		// Prethodni upit nalazi sve termine koji počinju sa "leo". U našem slučaju
		// vraća iste rezultate kao i naredni upit.
		parseClassicAndSearch("leo OR leon");
	}
	
	/**
	 * 6. Testiranje upita sa džoker znacima (wildcard). 
	 */
	public void testWildcardQueries() {

		// Ovi upiti sadrže džoker (wildcard) karaktere:
		// * označava od 0 do više proizvoljnih karaktera (slično kao u jeziku
		// regularnih izraza);
		// ? označava tačno 1 proizvoljni karakter. 
		// Za razliku od prefix upita ovde džoker karakteri mogu da se nađu bilo gde u
		// terminu, a ne samo na kraju termina.

		WildcardQuery wildcardQuery1 = new WildcardQuery(new Term(POLJE_SADRZAJ, "vronsk?"));
		searchIndex(wildcardQuery1);
		// Isti upit u tekstualnom formatu
		parseClassicAndSearch(POLJE_SADRZAJ + ":vronsk?");

		WildcardQuery wildcardQuery2 = new WildcardQuery(new Term(POLJE_SADRZAJ, "vronsk*"));
		searchIndex(wildcardQuery2);
		// Isti upit u tekstualnom formatu, samo će tekst u ovom slučaju biti parsiran
		// kao PrefixQuery, a ne kao WildcardQuery
		parseClassicAndSearch(POLJE_SADRZAJ + ":vronsk*");

		WildcardQuery wildcardQuery3 = new WildcardQuery(new Term(POLJE_SADRZAJ, "vro?sky"));
		searchIndex(wildcardQuery3);
		// Isti upit u tekstualnom formatu
		parseClassicAndSearch(POLJE_SADRZAJ + ":vro?sky");

		WildcardQuery wildcardQuery4 = new WildcardQuery(new Term(POLJE_SADRZAJ, "vro*sky"));
		searchIndex(wildcardQuery4);
		// Isti upit u tekstualnom formatu
		parseClassicAndSearch(POLJE_SADRZAJ + ":vro*sky");

		WildcardQuery wildcardQuery5 = new WildcardQuery(new Term(POLJE_SADRZAJ, "?ronsky"));
		searchIndex(wildcardQuery5);
		// Parseri ne dozvoljavaju džoker znak na početku termina pa bi naredni upit
		// generisao izuzetak.
		// parseClassicAndSearch(POLJE_SADRZAJ + ":?ronsky");

		WildcardQuery wildcardQuery6 = new WildcardQuery(new Term(POLJE_SADRZAJ, "*ronsky"));
		searchIndex(wildcardQuery6);
		// Parseri ne dozvoljavaju džoker znak na početku termina pa bi naredni upit
		// generisao izuzetak.
		// parseClassicAndSearch(POLJE_SADRZAJ + ":*ronsky");
	}
	
	/**
	 * 7. Testiranje upita sa frazama (phrase query). 
	 */
	public void testPhraseQueries() {

		// Ovi upiti traže tačnu frazu koja se sastoji iz više termina.
		PhraseQuery.Builder phraseQueryBuilder = new PhraseQuery.Builder();
		phraseQueryBuilder.add(new Term(POLJE_NASLOV, "karenina"), 0); // ovaj termin se zadaje na poziciji 0
		phraseQueryBuilder.add(new Term(POLJE_NASLOV, "anna"), 1); // ovaj termin se zadaje na poziciji 1
		// Dakle tražimo tačnu frazu "karenina anna" u naslovu i zbog toga nema rezultata
		PhraseQuery phraseQuery = phraseQueryBuilder.build();
		searchIndex(phraseQuery);
		// Isti upit u tekstualnom formatu
		parseClassicAndSearch(POLJE_NASLOV + ":\"karenina anna\"");

		// Možemo da zadamo "slop" faktor za upit. "Slop" predstavlja ukupan broj
		// potrebnih pomeranja termina (svako pomeranje pomera termin za jednu poziciju
		// u nizu termina) iz osnovne fraze da bi se od osnovne fraze dobila fraza 
		// koja je pronađena u dokumentu. 
		// Podrazumevana vrednost za "slop" je 0. Ako je postavimo na 1 omogućićemo
		// pronalaženje (pored osnovne fraze "karenina anna") i naredne fraze:
		// "karenina <bilo_koji_termin> anna"
		
		phraseQueryBuilder.setSlop(1);
		PhraseQuery phraseQuery1 = phraseQueryBuilder.build();
		searchIndex(phraseQuery1); // ni ovaj upit neće vratiti rezultate
		
		// Ako povećamo slop na 2 omogućićemo dva pomeranja i pronalaženje
		// (pored osnovne fraze "karenina anna") i narednih fraza:
		// "karenina <bilo_koji_termin> anna"
		// "karenina <bilo_koji_termin> <bilo_koji_termin> anna"
		// "anna karenina" - transpozicija dva termina ima "slop" vrednost 2
		phraseQueryBuilder.setSlop(2);
		PhraseQuery phraseQuery2 = phraseQueryBuilder.build();
		searchIndex(phraseQuery2); // ovaj upit vraća rezultat
		
		// Isti upit u tekstualnom formatu
		parseClassicAndSearch(POLJE_NASLOV + ":\"karenina anna\"~2");
		
		// Vrednost za slop veća od broja reči u svakom od dokumenata ponaosob
		// radi isto što i AND upit nad terminima iz fraze. 
		parseClassicAndSearch("\"karenina anna\"~1000000");
	}
	
	/**
	 * 8. Testiranje nedeterminističkih (fuzzy) upita. 
	 */
	public void testFuzzyQueries() {
		// Fuzzy upit pretražuje slične termine datom terminu. Kao mera različitosti
		// termina koji tražimo i termina koji je pronađen uzima se "edit distance" 
		// rastojanje (Damerau–Levenshtein rastojanje). Edit distance je jednak broju 
		// minimalno potrebnih edit operacija nad karakterima jednog od stringova 
		// da bi traženi string postao isti kao i pronađeni string. Svaka od navedenih 
		// operacija ima težinu 1:
		// -brisanje jednog karaktera (osoba->soba)
		// -umetanje jednog karaktera (rad->grad)
		// -zamena jednog karaktera karakterom sa iste pozicije iz drugog stringa (mače->meče)
		// -transpozicija - zamena dva susedna karaktera iz istog stringa (dobar->dobra)
		
		// Najveće dozvoljeno rastojanje između termina koji se traži i termina koji 
		// je pronađen je 2. 
		
		// Primer sa rastojanjem 1
		FuzzyQuery fuzzyQuery1 = new FuzzyQuery(new Term(POLJE_SADRZAJ, "karenina"), 1);
		searchIndex(fuzzyQuery1);
		
		// Primer sa rastojanjem 2
		FuzzyQuery fuzzyQuery2 = new FuzzyQuery(new Term(POLJE_SADRZAJ, "karenina"), 2);
		searchIndex(fuzzyQuery2);
		
		// Isti upit u tekstualnom formatu
		// Ovde se ~ piše pre kraja upita, NE POSLE znaka " kao kod Phrase upita
		// Traže se reči slične reči hamlet i vraćaju se dokumenti koji ih sadrže
		parseClassicAndSearch("karenina~2");

	}
	
}
