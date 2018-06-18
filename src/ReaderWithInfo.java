import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;

public class ReaderWithInfo extends BufferedReader{

	private static final String LINE_BREAK = "\n";	
	public ReaderWithInfo(Reader reader) {
		super(reader);
	}
	
	
	public String readLine(String someText) throws IOException {
		System.out.println(someText + LINE_BREAK);
		return super.readLine();
	}
	
	@Override
	public String readLine() throws IOException {
		return super.readLine();
	}
}
