public class Start {
	public static void main(String[] args) {
		
		String funcao = getFunctionType(args);
		String ipServidor = getIpServer(args);
		String porta = getServerPort(args);
		
		if("Cliente".equalsIgnoreCase(funcao)) {
			try {
				Alice.startClient(ipServidor, porta);
			} catch (Exception e) {
				e.printStackTrace();
			} 
		}else {
			try {
				Bob.startServer(ipServidor, porta);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
	}
	
	private static String getFunctionType(String[] args) {
		return args[args.length - 3];
	}
	
	private static String getIpServer(String[] args) {
		return args[args.length - 2];
	}
	
	private static String getServerPort(String[] args) {
		return args[args.length - 1];
	}
	
	
}
