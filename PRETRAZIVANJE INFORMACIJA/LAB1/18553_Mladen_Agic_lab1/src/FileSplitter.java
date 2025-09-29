import java.io.*;
import java.nio.file.*;

public class FileSplitter {
	
	 public static void main(String[] args) {

	        String inputFolderPath = BaseConfig.DIREKTORIJUM_SA_PODACIMA; 
	        
	        String outputFolderPath = BaseConfig.DIREKTORIJUM_SA_PODELJENIM_PODACIMA;

	        File inputFolder = new File(inputFolderPath);
	        File[] files = inputFolder.listFiles((dir, name) -> name.endsWith(".txt"));

	        if (files == null || files.length == 0) {
	            System.out.println("Nema .txt fajlova u folderu " + inputFolderPath);
	            return;
	        }

	        new File(outputFolderPath).mkdirs();

	        int globalCounter = 0; //od  1 do 400

	        for (File file : files) {
	            try {
	           
	                String content = new String(Files.readAllBytes(file.toPath()));
	                int length = content.length();
	                int partSize = length / 100;

	                for (int i = 0; i < 100; i++) {
	                    int start = i * partSize;
	                    int end = (i == 99) ? length : (i + 1) * partSize; // poslednji deo uzima ostatak
	                    String partContent = content.substring(start, end);
	                 
	                    String newFileName = String.format("deo_%04d.txt", ++globalCounter);
	                    File outputFile = new File(outputFolderPath, newFileName);

	                    try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
	                        writer.write(partContent);
	                    }
	                }

	                System.out.println("Fajl " + file.getName() + " je podeljen na 100 delova.");

	            } catch (IOException e) {
	                System.err.println("Greška prilikom obrade fajla: " + file.getName());
	                e.printStackTrace();
	            }
	        }

	        System.out.println("Ukupno fajlova kreirano: " + globalCounter);
	    }

}
