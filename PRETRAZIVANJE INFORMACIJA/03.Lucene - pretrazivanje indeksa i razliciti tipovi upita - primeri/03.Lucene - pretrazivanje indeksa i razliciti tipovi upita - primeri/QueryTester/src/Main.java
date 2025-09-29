
public class Main {

	public static void main(String[] args) {
		
		Indexer indexer = new Indexer(); 
		indexer.createIndex();

		try (Searcher searcher = new Searcher()) {
			searcher.testTermQueries();
			searcher.testBooleanQueries();
			searcher.testTermRangeQueries();
			searcher.testPointRangeQueries();
			searcher.testPrefixQueries();
			searcher.testWildcardQueries();
			searcher.testPhraseQueries();
			searcher.testFuzzyQueries();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
